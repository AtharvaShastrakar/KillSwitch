package main

// Regression tests for the agent. Run: go test ./...  (from the agent folder)
import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var keyRE = keyLineRE // keep the parser and the server's format in one place

// fakeServer mirrors services.heartbeat escrow rules: stores only valid 48-digit keys, and
// escrowConfirmed = stored key ID == reported key ID.
type fakeServer struct {
	mu       sync.Mutex
	storedID string
	stored   string
	acks     []map[string]any
	commands []Envelope
}

func (f *fakeServer) start(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if strings.HasSuffix(r.URL.Path, "/ack") {
			f.acks = append(f.acks, body)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
			return
		}
		id, _ := body["recoveryKeyId"].(string)
		rejected := false
		if k, ok := body["recoveryKey"].(string); ok {
			if len(k) == 55 && !strings.ContainsAny(k, " \n") {
				f.stored, f.storedID = k, id
			} else {
				rejected = true
			}
		}
		cmds := f.commands
		f.commands = nil
		_ = json.NewEncoder(w).Encode(map[string]any{
			"state": "ACTIVE", "escrowConfirmed": !rejected && f.stored != "" && f.storedID == id, "commands": cmds,
		})
	}))
	t.Cleanup(ts.Close)
	return ts
}

type fakeExec struct {
	id, key     string
	lockErr     error
	locked      bool
	rebooted    bool
	rotateTo    [2]string
	lockOrdered []string
}

func (e *fakeExec) Serial() (string, error)              { return "SER1", nil }
func (e *fakeExec) Encryption() string                   { return "BitLocker On" }
func (e *fakeExec) RecoveryKey() (string, string, error) { return e.id, e.key, nil }
func (e *fakeExec) Wipe() error                          { return nil }
func (e *fakeExec) Reboot() error {
	e.rebooted = true
	e.lockOrdered = append(e.lockOrdered, "reboot")
	return nil
}
func (e *fakeExec) Lock(string) error {
	e.lockOrdered = append(e.lockOrdered, "lock")
	if e.lockErr != nil {
		return e.lockErr
	}
	e.locked = true
	return nil
}
func (e *fakeExec) Unlock() error {
	e.id, e.key = e.rotateTo[0], e.rotateTo[1]
	e.locked = false
	return nil
}

const (
	realID  = "{29FFE490-5071-4C60-BE5A-99811F2C64D5}"
	realKey = "167893-066264-291797-706662-447117-680856-595320-439703"
	newID   = "{E7AB6754-E354-4B9D-952A-7DE9AD08C5DB}"
	newKey  = "366586-075152-655435-422587-094974-614284-201135-301576"
)

func newTestAgent(t *testing.T, url string, ex Executor, dry bool, priv ed25519.PrivateKey) *Agent {
	pub := priv.Public().(ed25519.PublicKey)
	a := &Agent{pub: pub, dryRun: dry, statePath: filepath.Join(t.TempDir(), "state.json"), exec: ex, api: NewClient(url)}
	a.cfg.HeartbeatSeconds = 900
	a.st.DeviceToken, a.st.DeviceID, a.st.Serial = "tok", 1, "SER1"
	a.st.SeenCommands = map[string]int64{}
	return a
}

func sign(t *testing.T, priv ed25519.PrivateKey, v any) Envelope {
	b, _ := json.Marshal(v)
	return Envelope{Payload: base64.StdEncoding.EncodeToString(b), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))}
}

func lockCmd(t *testing.T, priv ed25519.PrivateKey) Envelope {
	return sign(t, priv, map[string]any{"kind": "command", "id": "c1", "action": "lock", "deviceId": 1, "serial": "SER1",
		"expiresAt": time.Now().Add(time.Hour).UnixMilli()})
}

func TestDryRunFakeKeyIsReplacedByRealKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	srv := &fakeServer{}
	ts := srv.start(t)
	real := &fakeExec{id: realID, key: realKey}
	a := newTestAgent(t, ts.URL, &dryRunExecutor{real: real}, true, priv)
	if err := a.heartbeat(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(srv.storedID, "dry-run-") {
		t.Fatalf("dry run should escrow a dry-run ID, got %q", srv.storedID)
	}
	a.dryRun, a.exec = false, real // admin switches dryRun off
	_ = a.heartbeat()
	if srv.stored != realKey || srv.storedID != realID || !a.st.EscrowConfirmed {
		t.Fatalf("real key not escrowed after switching off dry run: stored=%q id=%q confirmed=%v", srv.stored, srv.storedID, a.st.EscrowConfirmed)
	}
}

func TestRotatedKeyIsEscrowedAfterUnlock(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	srv := &fakeServer{}
	ts := srv.start(t)
	ex := &fakeExec{id: realID, key: realKey, rotateTo: [2]string{newID, newKey}}
	a := newTestAgent(t, ts.URL, ex, false, priv)
	_ = a.heartbeat()
	a.st.SelfLocked = true
	if _, err := a.restore(); err != nil {
		t.Fatal(err)
	}
	_ = a.heartbeat()
	if srv.stored != newKey || !a.st.EscrowConfirmed || a.st.EscrowedKeyID != newID {
		t.Fatalf("rotated key not escrowed: stored=%q confirmed=%v", srv.stored, a.st.EscrowConfirmed)
	}
}

func TestKeyChangedOutsideAgentIsDetected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	srv := &fakeServer{}
	ts := srv.start(t)
	ex := &fakeExec{id: realID, key: realKey}
	a := newTestAgent(t, ts.URL, ex, false, priv)
	_ = a.heartbeat()
	ex.id, ex.key = newID, newKey // e.g. someone re-enabled BitLocker by hand
	_ = a.heartbeat()
	if srv.stored != newKey {
		t.Fatalf("server still has the old key after the laptop's key changed")
	}
}

func TestFailedLockIsReportedAsFailedAndDoesNotReboot(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	srv := &fakeServer{}
	ts := srv.start(t)
	ex := &fakeExec{id: realID, key: realKey, lockErr: errors.New("BitLocker protection is not On; refusing to lock")}
	a := newTestAgent(t, ts.URL, ex, false, priv)
	_ = a.heartbeat()
	srv.commands = []Envelope{lockCmd(t, priv)}
	_ = a.heartbeat()
	if len(srv.acks) != 1 || srv.acks[0]["ok"] != false {
		t.Fatalf("expected exactly one FAILED ack, got %v", srv.acks)
	}
	if ex.rebooted || a.st.SelfLocked {
		t.Fatal("must not reboot or mark self-locked when the lock failed")
	}
}

func TestLockAcksSuccessOnlyAfterTPMRemovedThenReboots(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	srv := &fakeServer{}
	ts := srv.start(t)
	ex := &fakeExec{id: realID, key: realKey}
	a := newTestAgent(t, ts.URL, ex, false, priv)
	_ = a.heartbeat()
	srv.commands = []Envelope{lockCmd(t, priv)}
	_ = a.heartbeat()
	if len(srv.acks) != 1 || srv.acks[0]["ok"] != true || !ex.locked || !ex.rebooted || !a.st.SelfLocked {
		t.Fatalf("lock flow wrong: acks=%v locked=%v rebooted=%v", srv.acks, ex.locked, ex.rebooted)
	}
	if strings.Join(ex.lockOrdered, ",") != "lock,reboot" {
		t.Fatalf("order = %v", ex.lockOrdered)
	}
}

func TestLockRefusedWhenServerDoesNotHoldCurrentKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	srv := &fakeServer{}
	ts := srv.start(t)
	ex := &fakeExec{id: realID, key: "not-a-valid-key"} // server rejects it -> never confirmed
	a := newTestAgent(t, ts.URL, ex, false, priv)
	srv.commands = []Envelope{lockCmd(t, priv)}
	_ = a.heartbeat()
	if ex.locked || len(srv.acks) != 1 || srv.acks[0]["ok"] != false {
		t.Fatalf("agent locked without a confirmed escrow: locked=%v acks=%v", ex.locked, srv.acks)
	}
}

func TestParseKeyLineIgnoresPowerShellNoise(t *testing.T) {
	out := "WARNING: ACTIONS REQUIRED:\n 1. Save this numerical recovery password ...\n\n" + newKey +
		"\n\nKSKEY {e7ab6754-e354-4b9d-952a-7de9ad08c5db} " + newKey + "\n"
	id, key, err := parseKeyLine(out)
	if err != nil || id != newID || key != newKey {
		t.Fatalf("got id=%q key=%q err=%v", id, key, err)
	}
	if _, _, err := parseKeyLine("WARNING: something\n" + newKey); err == nil {
		t.Fatal("a key without the KSKEY marker and ID must be rejected")
	}
	_ = keyRE
}
