#Requires -RunAsAdministrator
# Ставит "VPN Bypass Agent" как задачу планировщика: старт при входе в систему, с правами админа.
$ErrorActionPreference = "Stop"
$here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$agent = Join-Path $here "vpn-bypass-agent.mjs"
$cfg   = Join-Path $here "config.json"
$vbs   = Join-Path $here "run-hidden.vbs"
$task  = "VPN Bypass Agent"

$node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
if (-not $node) { $node = "C:\Program Files\nodejs\node.exe" }
if (-not (Test-Path $node))  { throw "node.exe не найден. Установите Node.js LTS." }
if (-not (Test-Path $agent)) { throw "Не найден $agent" }

if (-not (Test-Path $cfg)) {
  Copy-Item (Join-Path $here "config.example.json") $cfg
  Write-Host "Создан config.json (из примера)."
}

New-Item -ItemType Directory -Force -Path "C:\ProgramData\vpn-bypass-agent" | Out-Null

# Снять прежнюю задачу и все запущенные экземпляры агента, чтобы не плодить копии.
Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -like "*vpn-bypass-agent.mjs*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Remove-Item "C:\ProgramData\vpn-bypass-agent\agent.lock" -ErrorAction SilentlyContinue

# Скрытый запуск без мелькающего окна консоли.
@"
' Автогенерируется install.ps1 — запускает агента в скрытом окне.
Dim sh : Set sh = CreateObject("WScript.Shell")
sh.Run """$node"" ""$agent""", 0, False
"@ | Set-Content -Path $vbs -Encoding ASCII

$action    = New-ScheduledTaskAction -Execute "wscript.exe" -Argument """$vbs""" -WorkingDirectory $here
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) `
                -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
                -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $task

Write-Host ""
Write-Host "Готово. Задача '$task' зарегистрирована и запущена."
$listPath = [Environment]::ExpandEnvironmentVariables((Get-Content $cfg | ConvertFrom-Json).listPath)
Write-Host "Лог:    C:\ProgramData\vpn-bypass-agent\agent.log"
Write-Host "Список: $listPath"
Write-Host "Проверка статуса:  node `"$agent`" --status"
