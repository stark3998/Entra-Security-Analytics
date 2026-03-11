<#
.SYNOPSIS
    Automated startup script for Log Analytics (backend + frontend).

.DESCRIPTION
    - Creates/activates the Python virtual environment and installs backend deps
    - Installs frontend npm dependencies if needed
    - Copies .env.example → .env if .env doesn't exist
    - Starts the FastAPI backend and Vite dev server in parallel
    - Opens the browser to the frontend URL
    - Ctrl+C gracefully stops both processes

.PARAMETER SkipInstall
    Skip dependency installation (faster restart when deps haven't changed).

.PARAMETER Daemon
    Start the backend in daemon mode (scheduler + server) instead of server-only.

.PARAMETER BackendOnly
    Start only the backend, skip the frontend.

.PARAMETER FrontendOnly
    Start only the frontend, skip the backend.

.EXAMPLE
    .\start.ps1
    .\start.ps1 -SkipInstall
    .\start.ps1 -Daemon
    .\start.ps1 -BackendOnly
#>

param(
    [switch]$SkipInstall = $true,
    [switch]$Daemon,
    [switch]$BackendOnly,
    [switch]$FrontendOnly
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $root "backend"
$frontendDir = Join-Path $root "frontend"

# ── Colors ──────────────────────────────────────────────────────────
function Write-Step($msg)  { Write-Host "`n[$([char]0x2713)] $msg" -ForegroundColor Cyan }
function Write-Info($msg)  { Write-Host "    $msg" -ForegroundColor Gray }
function Write-Warn($msg)  { Write-Host "    [!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg)  { Write-Host "    [x] $msg" -ForegroundColor Red }

# ── Prerequisite checks ────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Log Analytics - Startup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if (-not $FrontendOnly) {
    Write-Step "Checking Python..."
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) {
        Write-Fail "Python not found. Install Python >= 3.11 and ensure it's on PATH."
        exit 1
    }
    $pyVer = python --version 2>&1
    Write-Info $pyVer
}

if (-not $BackendOnly) {
    Write-Step "Checking Node.js..."
    $node = Get-Command node -ErrorAction SilentlyContinue
    if (-not $node) {
        Write-Fail "Node.js not found. Install Node.js >= 18 and ensure it's on PATH."
        exit 1
    }
    $nodeVer = node --version 2>&1
    Write-Info "Node $nodeVer"
}

# ── Backend setup ──────────────────────────────────────────────────
$backendJob = $null
if (-not $FrontendOnly) {
    Push-Location $backendDir

    # Virtual environment
    $venvPath = Join-Path $backendDir ".venv"
    $venvActivate = Join-Path $venvPath "Scripts\Activate.ps1"

    if (-not (Test-Path $venvPath)) {
        Write-Step "Creating Python virtual environment..."
        python -m venv .venv
    }

    Write-Step "Activating virtual environment..."
    & $venvActivate

    # Install dependencies
    if (-not $SkipInstall) {
        Write-Step "Installing backend dependencies..."
        pip install -e ".[dev]" --quiet 2>&1 | Out-Null
        Write-Info "Done."
    } else {
        Write-Info "Skipping dependency install (-SkipInstall)."
    }

    # .env file
    $envFile = Join-Path $backendDir ".env"
    $envExample = Join-Path $backendDir ".env.example"
    if (-not (Test-Path $envFile)) {
        if (Test-Path $envExample) {
            Write-Step "Creating .env from .env.example..."
            Copy-Item $envExample $envFile
            Write-Warn ".env created with placeholder values. Edit it or configure via the Settings page."
        } else {
            Write-Warn "No .env or .env.example found. The app will use defaults."
        }
    } else {
        Write-Info ".env file found."
    }

    # Start backend
    $backendCmd = if ($Daemon) { "log-analytics daemon" } else { "log-analytics serve --reload" }
    $backendLabel = if ($Daemon) { "daemon" } else { "server" }
    Write-Step "Starting backend ($backendLabel)..."

    $backendJob = Start-Job -ScriptBlock {
        param($dir, $cmd, $activate)
        Set-Location $dir
        & $activate
        Invoke-Expression $cmd
    } -ArgumentList $backendDir, $backendCmd, $venvActivate

    Write-Info "Backend PID: $($backendJob.Id) → http://localhost:8000"

    Pop-Location
}

# ── Frontend setup ─────────────────────────────────────────────────
$frontendJob = $null
if (-not $BackendOnly) {
    Push-Location $frontendDir

    # Install dependencies
    $nodeModules = Join-Path $frontendDir "node_modules"
    if (-not $SkipInstall -or -not (Test-Path $nodeModules)) {
        Write-Step "Installing frontend dependencies..."
        npm install --silent 2>&1 | Out-Null
        Write-Info "Done."
    } else {
        Write-Info "Skipping npm install (-SkipInstall)."
    }

    # Start frontend
    Write-Step "Starting frontend dev server..."

    $frontendJob = Start-Job -ScriptBlock {
        param($dir)
        Set-Location $dir
        npm run dev
    } -ArgumentList $frontendDir

    Write-Info "Frontend PID: $($frontendJob.Id) → http://localhost:5173"

    Pop-Location
}

# ── Wait for servers to be ready ───────────────────────────────────
Write-Step "Waiting for servers to start..."
Start-Sleep -Seconds 3

# Try to open browser
$frontendUrl = "http://localhost:5173"
if (-not $BackendOnly) {
    try {
        Start-Process $frontendUrl
        Write-Info "Opened browser to $frontendUrl"
    } catch {
        Write-Info "Open $frontendUrl in your browser."
    }
} else {
    Write-Info "Backend-only mode. API at http://localhost:8000"
    Write-Info "Health check:  http://localhost:8000/health"
}

# ── Status summary ─────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Log Analytics is running!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
if (-not $FrontendOnly) { Write-Host "  Backend API:   http://localhost:8000" -ForegroundColor White }
if (-not $BackendOnly)  { Write-Host "  Frontend:      http://localhost:5173" -ForegroundColor White }
if (-not $FrontendOnly) { Write-Host "  Health check:  http://localhost:8000/health" -ForegroundColor White }
Write-Host "  Settings page: http://localhost:5173/settings" -ForegroundColor White
Write-Host ""
Write-Host "  Press Ctrl+C to stop all servers." -ForegroundColor Yellow
Write-Host ""

# ── Tail logs until Ctrl+C ─────────────────────────────────────────
try {
    while ($true) {
        if ($backendJob) {
            $out = Receive-Job $backendJob -ErrorAction SilentlyContinue
            if ($out) { $out | ForEach-Object { Write-Host "[backend]  $_" -ForegroundColor DarkCyan } }
            if ($backendJob.State -eq "Failed") {
                Write-Fail "Backend process exited unexpectedly:"
                Receive-Job $backendJob -ErrorAction SilentlyContinue | Write-Host
                break
            }
        }
        if ($frontendJob) {
            $out = Receive-Job $frontendJob -ErrorAction SilentlyContinue
            if ($out) { $out | ForEach-Object { Write-Host "[frontend] $_" -ForegroundColor DarkMagenta } }
            if ($frontendJob.State -eq "Failed") {
                Write-Fail "Frontend process exited unexpectedly:"
                Receive-Job $frontendJob -ErrorAction SilentlyContinue | Write-Host
                break
            }
        }
        Start-Sleep -Milliseconds 500
    }
} finally {
    # Graceful shutdown
    Write-Host ""
    Write-Step "Shutting down..."
    if ($backendJob)  { Stop-Job $backendJob  -ErrorAction SilentlyContinue; Remove-Job $backendJob  -Force -ErrorAction SilentlyContinue; Write-Info "Backend stopped." }
    if ($frontendJob) { Stop-Job $frontendJob -ErrorAction SilentlyContinue; Remove-Job $frontendJob -Force -ErrorAction SilentlyContinue; Write-Info "Frontend stopped." }
    Write-Host "  Goodbye!" -ForegroundColor Cyan
}
