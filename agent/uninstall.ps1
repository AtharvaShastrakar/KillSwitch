#Requires -RunAsAdministrator
$ErrorActionPreference = 'SilentlyContinue'
Stop-ScheduledTask -TaskName 'KillSwitchAgent'
Unregister-ScheduledTask -TaskName 'KillSwitchAgent' -Confirm:$false
Stop-Process -Name 'killswitch-agent' -Force
Remove-Item (Join-Path $env:ProgramFiles 'KillSwitch') -Recurse -Force
Write-Host 'KillSwitch agent removed.'
