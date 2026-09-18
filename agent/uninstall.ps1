#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"
$here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$agent = Join-Path $here "vpn-bypass-agent.mjs"
$task  = "VPN Bypass Agent"

Stop-ScheduledTask -TaskName $task
Unregister-ScheduledTask -TaskName $task -Confirm:$false

$node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
if (-not $node) { $node = "C:\Program Files\nodejs\node.exe" }
if (Test-Path $node) { & $node $agent --cleanup }

Write-Host "Задача '$task' удалена, bypass-маршруты сняты."
Write-Host "config.json и логи в C:\ProgramData\vpn-bypass-agent оставлены — удалите вручную при желании."
