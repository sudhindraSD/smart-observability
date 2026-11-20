# SentinelOps Slice 4 - one-click demo launcher.
# Starts all five demo surfaces in titled PowerShell windows:
#   1. Mock Chaos Stream      :9000  (hospital-b telemetry + chaos scenarios)
#   2. Box 2 Central SaaS     :8000  (HTTPS, self-signed certs/cert.pem)
#   3. Box 1 Collector A      :4001  (bank-a  / ap-south-1 / STREAM_MODE=live)
#   4. Box 1 Collector B      :4002  (hospital-b / eu-west-1 / STREAM_MODE=ws)
#   5. Box 2 React Dashboard  :3000  (Vite dev server with /api /ws /chaos proxies)

$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }
Set-Location $root

# --- preflight ---------------------------------------------------------------
$venvPython = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPython)) {
    Write-Host 'ERROR: .venv\Scripts\python.exe not found. Create the venv first:' -ForegroundColor Red
    Write-Host '  python -m venv .venv; .venv\Scripts\pip install -r requirements.txt' -ForegroundColor Red
    exit 1
}

$certFile = Join-Path $root 'certs\cert.pem'
$keyFile = Join-Path $root 'certs\key.pem'
if (-not (Test-Path $certFile) -or -not (Test-Path $keyFile)) {
    Write-Host 'Self-signed TLS certificate missing - generating certs\cert.pem + certs\key.pem ...' -ForegroundColor Yellow
    & $venvPython (Join-Path $root 'scripts\gen_certs.py')
}

$dataDir = Join-Path $root 'data'
if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Path $dataDir | Out-Null }
$liveLog = Join-Path $dataDir 'live_host.log'
if (-not (Test-Path $liveLog)) { New-Item -ItemType File -Path $liveLog | Out-Null }

# --- pre-flight: clear zombie listeners on the five demo ports ----------------
# A leftover plain-HTTP server on :8000 makes the Vite proxy die with
# ssl3_get_record:wrong version number, and anything still holding :3000 makes
# Vite silently bump to :3001. Kill whatever listens before launching.
$demoPorts = @(9000, 8000, 4001, 4002, 3000)
foreach ($port in $demoPorts) {
    $zombiePids = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($zombiePid in $zombiePids) {
        if ($zombiePid -eq $PID) { continue }
        $proc = Get-Process -Id $zombiePid -ErrorAction SilentlyContinue
        $procName = if ($proc) { $proc.ProcessName } else { 'unknown' }
        Write-Host "Stopping zombie listener on port ${port}: PID $zombiePid ($procName)" -ForegroundColor Yellow
        Stop-Process -Id $zombiePid -Force -ErrorAction SilentlyContinue
    }
}

# --- child window commands ---------------------------------------------------
# Each child: cd to repo root, title its window, set env vars, run the service.
# (powershell.exe consumes everything after -Command, so the multi-statement
# string survives being passed as one argument.)

$py = $venvPython

$cmdStream =
    "Set-Location '$root'; " +
    "`$host.UI.RawUI.WindowTitle = '1 - Mock Chaos Stream (:9000)'; " +
    "& '$py' -m uvicorn mock_stream.stream_server:app --host 0.0.0.0 --port 9000"

$cmdSaas =
    "Set-Location '$root'; " +
    "`$host.UI.RawUI.WindowTitle = '2 - Box 2 Central SaaS HTTPS (:8000)'; " +
    "& '$py' -m uvicorn saas.main:app --host 0.0.0.0 --port 8000 --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem"

$envCollectorA =
    "`$env:TENANT_ID = 'bank-a'; " +
    "`$env:REGION = 'ap-south-1'; " +
    "`$env:COLLECTOR_ID = 'col-blr-01'; " +
    "`$env:COLLECTOR_TOKEN = 'tok-bank-a-blr'; " +
    "`$env:COLLECTOR_PORT = '4001'; " +
    "`$env:COLLECTOR_DB_PATH = 'data/collector_bank_a.db'; " +
    "`$env:STREAM_MODE = 'live'; " +
    "`$env:LIVE_LOG_FILE = 'data/live_host.log'; " +
    "`$env:SAAS_BASE_URL = 'https://localhost:8000'; " +
    "`$env:SAAS_TLS_VERIFY = 'false'; " +
    "`$env:LOCAL_HMAC_SALT = 'bank-a-local-only-salt'"

$cmdCollectorA =
    "Set-Location '$root'; " +
    "`$host.UI.RawUI.WindowTitle = '3 - Box 1 Collector A - Bank A / India / LIVE (:4001)'; " +
    "$envCollectorA; " +
    "& '$py' -m uvicorn collector.main:app --host 0.0.0.0 --port 4001"

$envCollectorB =
    "`$env:TENANT_ID = 'hospital-b'; " +
    "`$env:REGION = 'eu-west-1'; " +
    "`$env:COLLECTOR_ID = 'col-fra-01'; " +
    "`$env:COLLECTOR_TOKEN = 'tok-hosp-b-fra'; " +
    "`$env:COLLECTOR_PORT = '4002'; " +
    "`$env:COLLECTOR_DB_PATH = 'data/collector_hosp_b.db'; " +
    "`$env:STREAM_MODE = 'ws'; " +
    "`$env:STREAM_URL = 'ws://localhost:9000/ws/stream/hospital-b'; " +
    "`$env:SAAS_BASE_URL = 'https://localhost:8000'; " +
    "`$env:SAAS_TLS_VERIFY = 'false'; " +
    "`$env:LOCAL_HMAC_SALT = 'hospital-b-local-only-salt'"

$cmdCollectorB =
    "Set-Location '$root'; " +
    "`$host.UI.RawUI.WindowTitle = '4 - Box 1 Collector B - Hospital B / EU / WS (:4002)'; " +
    "$envCollectorB; " +
    "& '$py' -m uvicorn collector.main:app --host 0.0.0.0 --port 4002"

$cmdDashboard =
    "Set-Location '$root\dashboard'; " +
    "`$host.UI.RawUI.WindowTitle = '5 - Box 2 React SaaS Dashboard (:3000)'; " +
    'npm run dev -- --port 3000 --strictPort'

# --- launch ------------------------------------------------------------------
Write-Host 'Launching SentinelOps demo stack ...' -ForegroundColor Cyan

Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmdStream
Start-Sleep -Seconds 1
Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmdSaas
Start-Sleep -Seconds 2
Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmdCollectorA
Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmdCollectorB
Start-Sleep -Seconds 1
Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmdDashboard

# --- URLs + judge helper -----------------------------------------------------
Write-Host ''
Write-Host 'Demo stack launched - clickable URLs:' -ForegroundColor Green
Write-Host '  React SaaS Dashboard  : http://localhost:3000'
Write-Host '  Collector A (Bank A)  : http://localhost:4001'
Write-Host '  Collector B (Hosp B)  : http://localhost:4002'
Write-Host '  Central SaaS API      : https://localhost:8000/healthz'
Write-Host '  Mock Chaos Stream     : http://localhost:9000'
Write-Host ''
Write-Host 'Judge secret injection - paste this line in any PowerShell window' -ForegroundColor Green
Write-Host 'to push a live secret through Bank A''s LIVE host log pipeline:'
Write-Host ""
Write-Host "  Add-Content -Path '$liveLog' -Value 'payment callback trace: Authorization: Bearer sk_live_98a7sd98a7sd password=hunter2xyz client_ip=10.20.4.15 result=declined'"
Write-Host ''
