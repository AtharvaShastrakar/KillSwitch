// KillSwitch agent: runs on each company laptop as SYSTEM / root.
//
//   - Enrolls with the server and sends a heartbeat every few seconds/minutes.
//   - Escrows the BitLocker recovery key to the server.
//   - Only obeys commands signed with the server's Ed25519 key (pinned in config.json).
//   - Offline safety net: if no valid signed lease is renewed before it expires
//     (default 7 days without check-in), the agent locks the laptop by itself.
//   - dryRun=true (default) only LOGS what it would do. Set it to false to really lock/wipe.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const agentVersion = "0.2.0"

type Config struct {
	ServerURL        string `json:"serverUrl"`
	ServerPublicKey  string `json:"serverPublicKey"`
	EnrollmentToken  string `json:"enrollmentToken"`
	HeartbeatSeconds int    `json:"heartbeatSeconds"`
	DryRun           *bool  `json:"dryRun"`
	StateFile        string `json:"stateFile,omitempty"`
	SerialOverride   string `json:"serialOverride,omitempty"` // testing only
}

type State struct {
	DeviceID        int              `json:"deviceId"`
	DeviceToken     string           `json:"deviceToken"`
	Serial          string           `json:"serial"`
	LeaseExpires    int64            `json:"leaseExpires"`
	EscrowConfirmed bool             `json:"escrowConfirmed"`
	EscrowedKeyID   string           `json:"escrowedKeyId,omitempty"` // ID of the recovery password the server confirmed
	SelfLocked      bool             `json:"selfLocked"`              // laptop is in locked mode (by command or offline lease)
	LockMessage     string           `json:"lockMessage"`
	MaxSeenTime     int64            `json:"maxSeenTime"`
	SeenCommands    map[string]int64 `json:"seenCommands"`
}

type Agent struct {
	cfg       Config
	pub       ed25519.PublicKey
	dryRun    bool
	statePath string
	st        State
	exec      Executor
	api       *Client
}

func main() {
	exe, _ := os.Executable()
	defCfg := filepath.Join(filepath.Dir(exe), "config.json")
	cfgPath := flag.String("config", defCfg, "path to config.json")
	once := flag.Bool("once", false, "run a single heartbeat cycle and exit")
	flag.Parse()

	a, err := newAgent(*cfgPath)
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}
	log.Printf("KillSwitch agent %s starting (dryRun=%v, server=%s)", agentVersion, a.dryRun, a.cfg.ServerURL)
	for {
		a.cycle()
		if *once {
			return
		}
		time.Sleep(time.Duration(a.cfg.HeartbeatSeconds) * time.Second)
	}
}

func newAgent(cfgPath string) (*Agent, error) {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.ServerURL == "" || cfg.ServerPublicKey == "" {
		return nil, errors.New("config needs serverUrl and serverPublicKey")
	}
	pk, err := base64.StdEncoding.DecodeString(cfg.ServerPublicKey)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return nil, errors.New("serverPublicKey must be a base64 32-byte Ed25519 key")
	}
	if cfg.HeartbeatSeconds <= 0 {
		cfg.HeartbeatSeconds = 900
	}
	dry := true // safe default
	if cfg.DryRun != nil {
		dry = *cfg.DryRun
	}
	if cfg.StateFile == "" {
		cfg.StateFile = filepath.Join(filepath.Dir(cfgPath), "state.json")
	}
	a := &Agent{cfg: cfg, pub: ed25519.PublicKey(pk), dryRun: dry, statePath: cfg.StateFile}
	a.api = NewClient(cfg.ServerURL)
	a.exec = NewExecutor(dry, cfg.SerialOverride)
	a.loadState()
	return a, nil
}

func (a *Agent) loadState() {
	b, err := os.ReadFile(a.statePath)
	if err == nil {
		_ = json.Unmarshal(b, &a.st)
	}
	if a.st.SeenCommands == nil {
		a.st.SeenCommands = map[string]int64{}
	}
}

func (a *Agent) saveState() {
	// Forget command IDs older than 7 days.
	cut := time.Now().Add(-7 * 24 * time.Hour).UnixMilli()
	for id, t := range a.st.SeenCommands {
		if t < cut {
			delete(a.st.SeenCommands, id)
		}
	}
	b, _ := json.MarshalIndent(a.st, "", "  ")
	tmp := a.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("save state: %v", err)
		return
	}
	_ = os.Rename(tmp, a.statePath)
}

func (a *Agent) cycle() {
	defer a.saveState()
	nowMs := time.Now().UnixMilli()

	// Tamper check: clock moved backwards by more than 10 minutes (to dodge lease expiry).
	if a.st.MaxSeenTime > 0 && nowMs < a.st.MaxSeenTime-10*60*1000 {
		log.Printf("ALERT: system clock moved backwards; treating as tampering")
		a.selfLock("clock rollback detected")
	}
	if nowMs > a.st.MaxSeenTime {
		a.st.MaxSeenTime = nowMs
	}

	if a.st.DeviceToken == "" {
		if err := a.enroll(); err != nil {
			log.Printf("enroll failed: %v", err)
			return
		}
	}

	if err := a.heartbeat(); err != nil {
		log.Printf("heartbeat failed: %v", err)
	}

	// Offline safety net: lease expired and we could not renew it.
	if a.st.LeaseExpires > 0 && time.Now().UnixMilli() > a.st.LeaseExpires {
		a.selfLock("offline lease expired")
	}
}

func (a *Agent) enroll() error {
	serial, err := a.exec.Serial()
	if err != nil {
		return fmt.Errorf("read serial: %w", err)
	}
	host, _ := os.Hostname()
	var res struct {
		DeviceID    int    `json:"deviceId"`
		DeviceToken string `json:"deviceToken"`
	}
	err = a.api.Post("/api/agent/enroll", "", map[string]any{
		"enrollmentToken": a.cfg.EnrollmentToken, "serial": serial, "hostname": host,
		"os": osName(), "agentVersion": agentVersion,
	}, &res)
	if err != nil {
		return err
	}
	a.st.DeviceID, a.st.DeviceToken, a.st.Serial = res.DeviceID, res.DeviceToken, serial
	a.st.EscrowConfirmed = false
	log.Printf("enrolled as device %d (serial %s)", res.DeviceID, serial)
	return nil
}

type heartbeatResp struct {
	State           string     `json:"state"`
	EscrowConfirmed bool       `json:"escrowConfirmed"`
	LockMessage     string     `json:"lockMessage"`
	Lease           *Envelope  `json:"lease"`
	Commands        []Envelope `json:"commands"`
}

func (a *Agent) heartbeat() error {
	host, _ := os.Hostname()
	body := map[string]any{
		"hostname": host, "agentVersion": agentVersion, "dryRun": a.dryRun,
		"encryption": a.exec.Encryption(), "lockState": map[bool]string{true: "self-locked", false: "normal"}[a.st.SelfLocked],
	}
	// Report the ID of the recovery password that is on the laptop RIGHT NOW, every time.
	// The server only confirms escrow if it holds that exact key; otherwise we send it.
	keyID, key, keyErr := a.exec.RecoveryKey()
	if keyErr != nil {
		log.Printf("cannot read recovery key: %v", keyErr)
	} else {
		body["recoveryKeyId"] = keyID
		if !a.st.EscrowConfirmed || keyID != a.st.EscrowedKeyID {
			body["recoveryKey"] = key
		}
	}

	var res heartbeatResp
	if err := a.api.Post("/api/agent/heartbeat", a.st.DeviceToken, body, &res); err != nil {
		var he *HTTPError
		if errors.As(err, &he) && he.Status == 401 {
			log.Printf("server no longer recognises this device; will re-enroll")
			a.st.DeviceToken = ""
		}
		return err
	}
	// Only trust the confirmation if we told the server which key we have.
	a.st.EscrowConfirmed = keyErr == nil && res.EscrowConfirmed
	if a.st.EscrowConfirmed {
		a.st.EscrowedKeyID = keyID
	} else {
		a.st.EscrowedKeyID = ""
	}
	if res.LockMessage != "" {
		a.st.LockMessage = res.LockMessage
	}

	if res.Lease != nil {
		var lease struct {
			Kind      string `json:"kind"`
			DeviceID  int    `json:"deviceId"`
			Serial    string `json:"serial"`
			IssuedAt  int64  `json:"issuedAt"`
			ExpiresAt int64  `json:"expiresAt"`
		}
		if err := res.Lease.Verify(a.pub, &lease); err != nil {
			log.Printf("REJECTED lease: %v", err)
		} else if lease.Kind != "lease" || lease.DeviceID != a.st.DeviceID || lease.Serial != a.st.Serial {
			log.Printf("REJECTED lease: not for this device")
		} else {
			a.st.LeaseExpires = lease.ExpiresAt
			if a.st.SelfLocked {
				// Server says the laptop is in good standing: restore normal boot.
				log.Printf("lease renewed after self-lock; restoring TPM protector")
				a.restore()
			}
		}
	}

	for _, env := range res.Commands {
		a.handleCommand(env)
	}
	return nil
}

func (a *Agent) handleCommand(env Envelope) {
	var c struct {
		Kind      string `json:"kind"`
		ID        string `json:"id"`
		Action    string `json:"action"`
		DeviceID  int    `json:"deviceId"`
		Serial    string `json:"serial"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if err := env.Verify(a.pub, &c); err != nil {
		log.Printf("REJECTED command (bad signature): %v", err)
		return
	}
	if c.Kind != "command" || c.DeviceID != a.st.DeviceID || c.Serial != a.st.Serial {
		log.Printf("REJECTED command %s: not addressed to this device", c.ID)
		return
	}
	if time.Now().UnixMilli() > c.ExpiresAt {
		log.Printf("REJECTED command %s: expired", c.ID)
		return
	}
	if _, seen := a.st.SeenCommands[c.ID]; seen {
		return // already executed (replay protection)
	}
	a.st.SeenCommands[c.ID] = time.Now().UnixMilli()
	a.saveState() // persist before acting: a wipe or reboot may follow

	log.Printf("executing signed command %s: %s", c.ID, c.Action)
	var err error
	result := ""
	switch c.Action {
	case "lock":
		if !a.st.EscrowConfirmed && !a.dryRun {
			err = errors.New("refusing to lock: the server does not hold this laptop's current recovery key")
			break
		}
		// 1) Remove the TPM protector and verify the disk now needs the recovery key.
		if err = a.exec.Lock(a.lockMessage()); err != nil {
			break // acked as FAILED below; the dashboard shows the failure
		}
		// 2) Only now report success, then reboot to the recovery screen.
		a.st.SelfLocked = true
		a.saveState()
		a.ack(c.ID, true, "locked: TPM protector removed; rebooting to recovery screen")
		if rerr := a.exec.Reboot(); rerr != nil {
			log.Printf("reboot failed (the laptop asks for the key at its next restart): %v", rerr)
		}
		return
	case "unlock":
		if !a.st.SelfLocked {
			result = "already unlocked"
		} else {
			result, err = a.restore()
		}
	case "wipe":
		a.ack(c.ID, true, "wipe started")
		if err = a.exec.Wipe(); err != nil {
			log.Printf("wipe failed: %v", err)
		}
		return
	default:
		err = fmt.Errorf("unknown action %q", c.Action)
	}
	if err != nil {
		result = err.Error()
	}
	a.ack(c.ID, err == nil, result)
}

func (a *Agent) restore() (string, error) {
	if err := a.exec.Unlock(); err != nil {
		log.Printf("restore failed: %v", err)
		return "", err
	}
	a.st.SelfLocked = false
	// The recovery key was rotated: force the next heartbeat to escrow the new one.
	a.st.EscrowConfirmed = false
	a.st.EscrowedKeyID = ""
	a.saveState()
	return "TPM protector restored; recovery key rotated", nil
}

func (a *Agent) selfLock(reason string) {
	if a.st.SelfLocked {
		return
	}
	if !a.st.EscrowConfirmed && !a.dryRun {
		log.Printf("cannot self-lock (%s): recovery key was never escrowed", reason)
		return
	}
	log.Printf("SELF-LOCK: %s", reason)
	a.st.SelfLocked = true
	a.saveState()
	if err := a.exec.Lock(a.lockMessage()); err != nil {
		log.Printf("self-lock failed: %v", err)
		a.st.SelfLocked = false
		a.saveState()
		return
	}
	if err := a.exec.Reboot(); err != nil {
		log.Printf("reboot failed (the laptop asks for the key at its next restart): %v", err)
	}
}

func (a *Agent) lockMessage() string {
	if a.st.LockMessage != "" {
		return a.st.LockMessage
	}
	return "This laptop is company property and has been locked. Please contact IT to return it."
}

func (a *Agent) ack(id string, ok bool, result string) {
	if err := a.api.Post("/api/agent/ack", a.st.DeviceToken, map[string]any{"commandId": id, "ok": ok, "result": result}, nil); err != nil {
		log.Printf("ack %s failed: %v", id, err)
	}
}
