//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// macOS and Linux: serial number is read for real; lock/wipe are NOT implemented in this
// prototype. On macOS a reliable lock/erase needs Apple MDM (DeviceLock / EraseDevice commands
// via Apple Business Manager enrollment). On Linux use LUKS key-slot removal.
type otherExecutor struct{}

func platformExecutor() Executor { return &otherExecutor{} }

var errUnsupported = errors.New("lock/wipe is only implemented for Windows in this prototype")

func (o *otherExecutor) Serial() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err != nil {
			return "", err
		}
		m := regexp.MustCompile(`"IOPlatformSerialNumber" = "([^"]+)"`).FindSubmatch(out)
		if m == nil {
			return "", errors.New("serial not found")
		}
		return string(m[1]), nil
	case "linux":
		b, err := os.ReadFile("/sys/class/dmi/id/product_serial")
		s := strings.TrimSpace(string(b))
		if err != nil || s == "" {
			return "", errors.New("serial not readable (run as root)")
		}
		return s, nil
	}
	return "", errUnsupported
}

func (o *otherExecutor) Encryption() string {
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("fdesetup", "status").Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return "unknown"
}

func (o *otherExecutor) RecoveryKey() (string, error) { return "", errUnsupported }
func (o *otherExecutor) Lock(string) error            { return errUnsupported }
func (o *otherExecutor) Unlock() (string, error)      { return "", errUnsupported }
func (o *otherExecutor) Wipe() error                  { return errUnsupported }
