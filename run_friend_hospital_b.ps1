param(
    [Parameter(Mandatory=$true)]
    [string]$HostIp
)

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Error ".venv not found. Create the venv and install dependencies first."
    exit 1
}

if (-not (Test-Path "certs\cert.pem")) {
    Write-Error "certs\cert.pem missing. Copy ONLY certs\cert.pem from the Host laptop into certs\ first."
    exit 1
}

New-Item -ItemType Directory -Force -Path "data" | Out-Null

Write-Host "Checking HTTPS TLS connection to https://${HostIp}:8000/healthz ..." -ForegroundColor Cyan
& .venv\Scripts\python.exe -c "import sys, httpx; r = httpx.get('https://${HostIp}:8000/healthz', verify='certs/cert.pem', timeout=5.0); print('TLS OK:', r.status_code, r.text); sys.exit(0 if r.status_code == 200 else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Error "TLS check failed. Verify: (1) both laptops on same hotspot, (2) firewall open on port 8000, (3) fresh cert.pem generated with --lan-ip ${HostIp}."
    exit 1
}

$env:TENANT_ID         = 'hospital-b'
$env:REGION            = 'eu-west-1'
$env:COLLECTOR_ID      = 'col-fra-01'
$env:COLLECTOR_TOKEN   = 'tok-hosp-b-fra'
$env:COLLECTOR_PORT    = '4002'
$env:COLLECTOR_DB_PATH = 'data/collector_hosp_b.db'
$env:STREAM_MODE       = 'ws'
$env:STREAM_URL        = "ws://${HostIp}:9000/ws/stream/hospital-b"
$env:SAAS_BASE_URL     = "https://${HostIp}:8000"
$env:SAAS_TLS_VERIFY   = 'certs/cert.pem'
$env:LOCAL_HMAC_SALT   = 'hospital-b-local-only-salt'

Write-Host "Starting Hospital B Collector (col-fra-01) -> http://localhost:4002" -ForegroundColor Green
& .venv\Scripts\python.exe -m uvicorn collector.main:app --host 0.0.0.0 --port 4002