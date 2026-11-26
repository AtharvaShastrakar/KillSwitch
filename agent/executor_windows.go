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

// All Add-/Remove-BitLockerKeyProtector calls discard their output AND warning stream:
// Add-BitLockerKeyProtector prints an "ACTIONS REQUIRED ... save this password" notice that would
// otherwise end up in the text we parse. The scripts print exactly one line: "<ID> <password>".
const recoveryKeyScript = `
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive
if ($v.ProtectionStatus -ne 'On') { throw 'BitLocker protection is not On for the system drive' }
$kp = $v.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword' | Select-Object -First 1
if (-not $kp) {
  $null = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue 3>$null
  $kp = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword' | Select-Object -First 1
}
Write-Output ("KSKEY " + $kp.KeyProtectorId + " " + $kp.RecoveryPassword)`

func (w *windowsExecutor) RecoveryKey() (string, string, error) {
	out, err := ps(recoveryKeyScript)
	if err != nil {
		return "", "", err
	}
	return parseKeyLine(out)
}

// Lock: show a custom message on the BitLocker recovery screen and remove the TPM protector,
// then VERIFY that protection is still On and no TPM protector is left (otherwise Windows could
// boot without the recovery key). Reboot is a separate step.
const lockScript = `
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive
if ($v.ProtectionStatus -ne 'On') { throw 'BitLocker protection is not On; refusing to lock' }
if (-not ($v.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')) { throw 'no recovery password protector; refusing to lock' }
$p = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
New-Item -Path $p -Force | Out-Null
Set-ItemProperty -Path $p -Name RecoveryKeyMessageSource -Value 2 -Type DWord
Set-ItemProperty -Path $p -Name RecoveryKeyMessage -Value $env:KS_MESSAGE -Type String
$v.KeyProtector | Where-Object { $_.KeyProtectorType -like 'Tpm*' } | ForEach-Object {
  $null = Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $_.KeyProtectorId -WarningAction SilentlyContinue 3>$null
}
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive
if ($v.KeyProtector | Where-Object { $_.KeyProtectorType -like 'Tpm*' }) { throw 'TPM protector is still present after removal' }
if ($v.ProtectionStatus -ne 'On') { throw 'BitLocker protection turned Off after removing the TPM protector' }
Write-Output 'KSLOCKED'`

func (w *windowsExecutor) Lock(message string) error {
	out, err := ps(lockScript, "KS_MESSAGE="+message)
	if err != nil {
		return err
	}
	if !strings.Contains(out, "KSLOCKED") {
		return fmt.Errorf("lock script did not confirm: %s", out)
	}
	return nil
}

func (w *windowsExecutor) Reboot() error {
	return exec.Command("shutdown.exe", "/r", "/t", "30", "/c", "This laptop has been locked by IT.").Run()
}

// Unlock (after IT typed the recovery key at boot): restore the TPM protector, make sure
// protection is On, and rotate the recovery password, because the old one has been seen by a person.
const unlockScript = `
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive
if (-not ($v.KeyProtector | Where-Object { $_.KeyProtectorType -like 'Tpm*' })) {
  $null = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -WarningAction SilentlyContinue 3>$null
}
$old = @($v.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
$null = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -WarningAction SilentlyContinue 3>$null
foreach ($k in $old) { $null = Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $k.KeyProtectorId -WarningAction SilentlyContinue 3>$null }
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name RecoveryKeyMessage,RecoveryKeyMessageSource -ErrorAction SilentlyContinue
if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -ne 'On') { $null = Resume-BitLocker -MountPoint $env:SystemDrive }
Write-Output 'KSUNLOCKED'`

func (w *windowsExecutor) Unlock() error {
	out, err := ps(unlockScript)
	if err != nil {
		return err
	}
	if !strings.Contains(out, "KSUNLOCKED") {
		return fmt.Errorf("unlock script did not confirm: %s", out)
	}
	return nil
}

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
