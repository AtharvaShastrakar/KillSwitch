# KillSwitch agent installer (run as Administrator on each Windows laptop).
# Put killswitch-agent.exe and config.json in the same folder as this script, then:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$src  = $PSScriptRoot
$dest = Join-Path $env:ProgramFiles 'KillSwitch'
$task = 'KillSwitchAgent'

foreach ($f in 'killswitch-agent.exe', 'config.json') {
  if (-not (Test-Path (Join-Path $src $f))) { throw "$f not found next to install.ps1" }
}

# 1. BitLocker must be on before the agent can escrow a recovery key.
$bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
if ($bl.ProtectionStatus -ne 'On') {
  Write-Warning "BitLocker is OFF on $env:SystemDrive. Turn it on first (Settings > Privacy & security > Device encryption, or manage-bde -on $env:SystemDrive)."
}

# 2. Copy files and lock the folder down to SYSTEM + Administrators only.
New-Item -ItemType Directory -Path $dest -Force | Out-Null
Copy-Item (Join-Path $src 'killswitch-agent.exe') $dest -Force
Copy-Item (Join-Path $src 'config.json') $dest -Force
icacls $dest /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

# 3. Run at startup as SYSTEM, restart automatically if it stops.
$action    = New-ScheduledTaskAction -Execute (Join-Path $dest 'killswitch-agent.exe') -WorkingDirectory $dest
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $task

Write-Host "KillSwitch agent installed in $dest and started." -ForegroundColor Green
Write-Host "Check the dashboard: the laptop should appear under Devices within a minute."
