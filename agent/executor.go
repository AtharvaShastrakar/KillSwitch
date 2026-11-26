package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
)

// Executor performs the real device actions for one operating system.
type Executor interface {
	Serial() (string, error)
	Encryption() string
	// RecoveryKey ensures a recovery password exists and returns its protector ID and the password.
	RecoveryKey() (id, key string, err error)
	// Lock removes the TPM protector so the next boot requires the recovery key, and verifies it.
	// It does NOT reboot; call Reboot afterwards.
	Lock(message string) error
	Reboot() error
	// Unlock restores the TPM protector and rotates the recovery password (read it with RecoveryKey).
	Unlock() error
	Wipe() error // irreversible factory reset
}

// NewExecutor returns the platform executor, wrapped in a dry-run executor unless dryRun is false.
func NewExecutor(dryRun bool, serialOverride string) Executor {
	real := platformExecutor()
	if dryRun {
		return &dryRunExecutor{real: real, serialOverride: serialOverride}
	}
	if serialOverride != "" {
		log.Printf("serialOverride is ignored when dryRun=false")
	}
	return real
}

// dryRunExecutor reads real information where it is safe, but only LOGS destructive actions.
type dryRunExecutor struct {
	real           Executor
	serialOverride string
	fakeID         string
	fakeKey        string
}

func (d *dryRunExecutor) Serial() (string, error) {
	if d.serialOverride != "" {
		return d.serialOverride, nil
	}
	if s, err := d.real.Serial(); err == nil && s != "" {
		return s, nil
	}
	h, _ := os.Hostname()
	return "DEMO-" + strings.ToUpper(h), nil
}

func (d *dryRunExecutor) Encryption() string { return "dry-run: " + d.real.Encryption() }

// In dry run the server gets a FAKE key with a "dry-run-..." ID. Because the ID can never match a real
// BitLocker protector ID, the real key is escrowed automatically as soon as dryRun is switched off.
func (d *dryRunExecutor) RecoveryKey() (string, string, error) {
	if d.fakeKey == "" {
		d.fakeID, d.fakeKey = fakeKeyID(), fakeRecoveryKey()
	}
	return d.fakeID, d.fakeKey, nil
}

func (d *dryRunExecutor) Lock(msg string) error {
	log.Printf("[DRY RUN] would set pre-boot message %q and remove the TPM protector", msg)
	return nil
}

func (d *dryRunExecutor) Reboot() error {
	log.Printf("[DRY RUN] would reboot to the BitLocker recovery screen")
	return nil
}

func (d *dryRunExecutor) Unlock() error {
	log.Printf("[DRY RUN] would re-add TPM protector and rotate the recovery password")
	d.fakeID, d.fakeKey = fakeKeyID(), fakeRecoveryKey()
	return nil
}

func (d *dryRunExecutor) Wipe() error {
	log.Printf("[DRY RUN] would trigger a protected factory reset (MDM_RemoteWipe doWipeProtected)")
	return nil
}

func fakeKeyID() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return fmt.Sprintf("dry-run-%x", n.Int64())
}

// 48-digit BitLocker-style recovery password (8 groups of 6 digits) for demos.
func fakeRecoveryKey() string {
	parts := make([]string, 8)
	for i := range parts {
		n, _ := rand.Int(rand.Reader, big.NewInt(1_000_000))
		parts[i] = fmt.Sprintf("%06d", n.Int64())
	}
	return strings.Join(parts, "-")
}
