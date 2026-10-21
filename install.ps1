# CADP one-click installer (Windows)
# Usage (PowerShell as Administrator):
#   irm https://raw.githubusercontent.com/LLYlab/CADP/main/install.ps1 | iex
# or:
#   .\install.ps1 -Dest C:\CADP -Port 8080

param(
    [string]$Dest = "C:\CADP",
    [int]$Port = 8080,
    [string]$Repo = "https://github.com/LLYlab/CADP"
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}

$zip = Join-Path $env:TEMP "cadp-main.zip"
$tmp = Join-Path $env:TEMP "cadp-extract"
Write-Host "[CADP] downloading $Repo ..."
Invoke-WebRequest -Uri "$Repo/archive/refs/heads/main.zip" -OutFile $zip -UseBasicParsing
if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $tmp -Force
$src = (Get-ChildItem $tmp -Directory | Select-Object -First 1).FullName

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Get-ChildItem $src -Force | Where-Object { $_.Name -ne "site" } |
    Copy-Item -Destination $Dest -Recurse -Force
if (-not (Test-Path (Join-Path $Dest "site"))) {
    Copy-Item (Join-Path $src "site") (Join-Path $Dest "site") -Recurse -Force
}

$python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $python) {
    throw "python.exe not found. Install Python 3.10+ and add it to PATH."
}
$pyDir = Split-Path $python
$pythonw = Join-Path $pyDir "pythonw.exe"
if (-not (Test-Path $pythonw)) { $pythonw = $python }

$config = Join-Path $Dest "config.json"
Write-Host "[CADP] initializing config ..."
& $python (Join-Path $Dest "cadp.py") --init-config --config $config --port $Port --root "site"
if ($LASTEXITCODE -ne 0) { throw "CADP config init failed." }

$taskName = "CADP"
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
$action = New-ScheduledTaskAction -Execute $pythonw `
    -Argument "`"$(Join-Path $Dest 'cadp.py')`" --config `"$config`"" `
    -WorkingDirectory $Dest
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

if (-not (Get-NetFirewallRule -DisplayName "CADP-allow-$Port" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "CADP-allow-$Port" -Direction Inbound -Protocol TCP `
        -LocalPort $Port -Action Allow -Profile Any | Out-Null
}

Start-Sleep -Seconds 2
$pwdFile = Join-Path $Dest "ADMIN_PASSWORD.txt"
$password = if (Test-Path $pwdFile) { (Get-Content $pwdFile -Raw).Trim() } else { "(see $pwdFile)" }
Write-Host ""
Write-Host "=============================================="
Write-Host " CADP installed"
Write-Host "  Site    : http://localhost:$Port/"
Write-Host "  Admin   : http://localhost:$Port/__cadp/admin"
Write-Host "  Password: $password"
Write-Host "  Folder  : $Dest"
Write-Host "  Task    : $taskName (auto-start)"
Write-Host "=============================================="
Write-Host "Put static files into $Dest\site\ ; tune via /__cadp/admin or config.json."
