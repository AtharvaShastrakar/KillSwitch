//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type windowsExecutor struct{}

func platformExecutor() Executor { return &windowsExecutor{} }

// ps runs a PowerShell script. Values are passed through environment variables, never
// concatenated into the script, so they cannot inject commands.
func ps(script string, env ...string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", "$ErrorActionPreference='Stop'; "+script)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return s, fmt.Errorf("%v: %s", err, s)
	}
	return s, nil
}

func (w *windowsExecutor) Serial() (string, error) {
	s, err := ps(`(Get-CimInstance -ClassName Win32_BIOS).SerialNumber`)
	if err == nil && s == "" {
		err = errors.New("empty serial number")
	}
	return s, err
}

func (w *windowsExecutor) Encryption() string {
	s, err := ps(`$v = Get-BitLockerVolume -MountPoint $env:SystemDrive; "BitLocker " + $v.ProtectionStatus + " (" + $v.VolumeStatus + ")"`)
	if err != nil {
		return "unknown"
	}
	return s
}

const recoveryKeyScript = `
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive
if ($v.ProtectionStatus -ne 'On') { throw 'BitLocker is not turned on for the system drive' }
$kp = $v.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword' | Select-Object -First 1
if (-not $kp) {
  Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector | Out-Null
  $kp = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword' | Select-Object -First 1
}
$kp.RecoveryPassword`

func (w *windowsExecutor) RecoveryKey() (string, error) { return ps(recoveryKeyScript) }

// Lock: show a custom message on the BitLocker recovery screen, remove the TPM protector
// (so Windows can no longer unlock the disk by itself) and reboot.
const lockScript = `
$p = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
New-Item -Path $p -Force | Out-Null
Set-ItemProperty -Path $p -Name RecoveryKeyMessageSource -Value 2 -Type DWord
Set-ItemProperty -Path $p -Name RecoveryKeyMessage -Value $env:KS_MESSAGE -Type String
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive
if ($v.ProtectionStatus -ne 'On') { throw 'BitLocker is not on; refusing to lock' }
if (-not ($v.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')) { throw 'no recovery password protector; refusing to lock' }
$v.KeyProtector | Where-Object { $_.KeyProtectorType -like 'Tpm*' } | ForEach-Object {
  Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $_.KeyProtectorId | Out-Null
}
shutdown.exe /r /t 30 /c "This laptop has been locked by IT."`

func (w *windowsExecutor) Lock(message string) error {
	_, err := ps(lockScript, "KS_MESSAGE="+message)
	return err
}

// Unlock (after IT typed the recovery key at boot): restore the TPM protector and rotate
// the recovery password, because the old one has been seen by a person.
const unlockScript = `
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive
if (-not ($v.KeyProtector | Where-Object { $_.KeyProtectorType -like 'Tpm*' })) {
  Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector | Out-Null
}
$old = @($v.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector | Out-Null
foreach ($k in $old) { Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $k.KeyProtectorId | Out-Null }
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name RecoveryKeyMessage,RecoveryKeyMessageSource -ErrorAction SilentlyContinue
(Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword' | Select-Object -First 1 -ExpandProperty RecoveryPassword`

func (w *windowsExecutor) Unlock() (string, error) { return ps(unlockScript) }

// Wipe: Windows' built-in protected remote wipe (same as Intune "Wipe"). Must run as SYSTEM.
const wipeScript = `
$ns = 'root\cimv2\mdm\dmmap'
$session = New-CimSession
$params = New-Object Microsoft.Management.Infrastructure.CimMethodParametersCollection
$params.Add([Microsoft.Management.Infrastructure.CimMethodParameter]::Create('param', '', 'String', 'In'))
$instance = Get-CimInstance -Namespace $ns -ClassName 'MDM_RemoteWipe' -Filter "ParentID='./Vendor/MSFT' and InstanceID='RemoteWipe'"
$session.InvokeMethod($ns, $instance, 'doWipeProtectedMethod', $params) | Out-Null`

func (w *windowsExecutor) Wipe() error {
	_, err := ps(wipeScript)
	return err
}
