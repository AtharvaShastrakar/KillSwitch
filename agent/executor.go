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
	RecoveryKey() (string, error) // ensure a recovery key exists and return it
	Lock(message string) error    // reversible: boot requires the recovery key
	Unlock() (newKey string, err error)
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

func (d *dryRunExecutor) RecoveryKey() (string, error) {
	if d.fakeKey == "" {
		d.fakeKey = fakeRecoveryKey()
	}
	return d.fakeKey, nil
}

func (d *dryRunExecutor) Lock(msg string) error {
	log.Printf("[DRY RUN] would set pre-boot message %q, remove TPM protector and reboot to the BitLocker recovery screen", msg)
	return nil
}

func (d *dryRunExecutor) Unlock() (string, error) {
	log.Printf("[DRY RUN] would re-add TPM protector and rotate the recovery password")
	d.fakeKey = fakeRecoveryKey()
	return d.fakeKey, nil
}

func (d *dryRunExecutor) Wipe() error {
	log.Printf("[DRY RUN] would trigger a protected factory reset (MDM_RemoteWipe doWipeProtected)")
	return nil
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
