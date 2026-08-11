$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Test-PythonCandidate {
    param([string]$Command, [string[]]$PrefixArgs = @())
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) { return $false }
    try {
        & $Command @PrefixArgs -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 2)" *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Resolve-Python {
    if (Test-PythonCandidate "python") { return @("python") }
    if (Test-PythonCandidate "py" @("-3")) { return @("py", "-3") }
    if (Test-PythonCandidate "python3") { return @("python3") }
    throw "Python 3.10+ was not found. Install Python 3.10 or newer and rerun MemoryGuard."
}

$launcher = Resolve-Python
$installArgs = @("scripts\self_install.py", "--with-mcp")
if (-not [string]::IsNullOrWhiteSpace($env:MEMORYGUARD_PORT)) {
    $installArgs += @("--port", $env:MEMORYGUARD_PORT)
}

Write-Host "Installing and verifying MemoryGuard..." -ForegroundColor Cyan
if ($launcher.Count -eq 2) {
    & $launcher[0] $launcher[1] @installArgs
} else {
    & $launcher[0] @installArgs
}
if ($LASTEXITCODE -ne 0) { throw "MemoryGuard installation/verification failed. Review the output above." }

if (-not (Test-Path "installation-result.json")) { throw "Installer did not produce installation-result.json." }
$result = Get-Content "installation-result.json" -Raw | ConvertFrom-Json
if (-not $result.installed -or -not $result.tests_passed) { throw "MemoryGuard did not pass mandatory installation verification." }
if (-not (Test-Path $result.runtime_python)) { throw "Verified Python runtime is missing: $($result.runtime_python)" }

$env:MEMORYGUARD_SECRET = (Get-Content ".memoryguard-secret" -Raw).Trim()
$env:MEMORYGUARD_OPERATOR_KEY = (Get-Content ".memoryguard-operator-key" -Raw).Trim()
$env:MEMORYGUARD_DB = Join-Path $PSScriptRoot "memoryguard.db"
$env:MEMORYGUARD_HOST = if ($env:MEMORYGUARD_HOST) { $env:MEMORYGUARD_HOST } else { "127.0.0.1" }
$env:MEMORYGUARD_PORT = [string]$result.port

Write-Host "Running final startup diagnostics..." -ForegroundColor Cyan
& $result.runtime_python scripts\doctor.py --startup
if ($LASTEXITCODE -ne 0) { throw "Startup diagnostics failed. MemoryGuard was not started." }

$url = "http://127.0.0.1:$($result.port)"
Write-Host "MemoryGuard v$($result.version) starting at $url" -ForegroundColor Green
Write-Host "API docs: $url/docs" -ForegroundColor DarkGray
if ($result.warnings.Count -gt 0) {
    foreach ($warning in $result.warnings) { Write-Warning $warning }
}

Start-Job -ScriptBlock {
    param($u)
    for ($i=0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 1 "$u/health"
            if ($r.StatusCode -eq 200) { Start-Process $u; return }
        } catch {}
    }
} -ArgumentList $url | Out-Null

& $result.runtime_python -m uvicorn memoryguard.app:app --host $env:MEMORYGUARD_HOST --port $result.port
if ($LASTEXITCODE -ne 0) { throw "MemoryGuard server exited with code $LASTEXITCODE." }
