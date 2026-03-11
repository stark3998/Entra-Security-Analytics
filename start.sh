#!/usr/bin/env bash
#
# Automated startup script for Log Analytics (backend + frontend).
#
# Usage:
#   ./start.sh                  # Normal start (both services)
#   ./start.sh --skip-install   # Skip pip/npm install
#   ./start.sh --daemon         # Backend in daemon mode (scheduler + server)
#   ./start.sh --backend-only   # Skip frontend
#   ./start.sh --frontend-only  # Skip backend
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$ROOT/backend"
FRONTEND_DIR="$ROOT/frontend"

SKIP_INSTALL=false
DAEMON=false
BACKEND_ONLY=false
FRONTEND_ONLY=false

BACKEND_PID=""
FRONTEND_PID=""

# ── Parse args ─────────────────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --skip-install) SKIP_INSTALL=true ;;
        --daemon)       DAEMON=true ;;
        --backend-only) BACKEND_ONLY=true ;;
        --frontend-only) FRONTEND_ONLY=true ;;
        -h|--help)
            echo "Usage: $0 [--skip-install] [--daemon] [--backend-only] [--frontend-only]"
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

# ── Colors ─────────────────────────────────────────────────────────
step()  { printf "\n\033[36m[✓] %s\033[0m\n" "$1"; }
info()  { printf "    \033[90m%s\033[0m\n" "$1"; }
warn()  { printf "    \033[33m[!] %s\033[0m\n" "$1"; }
fail()  { printf "    \033[31m[✗] %s\033[0m\n" "$1"; }

# ── Cleanup on exit ────────────────────────────────────────────────
cleanup() {
    echo ""
    step "Shutting down..."
    [ -n "$BACKEND_PID" ]  && kill "$BACKEND_PID"  2>/dev/null && info "Backend stopped."
    [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null && info "Frontend stopped."
    wait 2>/dev/null
    info "Goodbye!"
}
trap cleanup EXIT INT TERM

# ── Banner ─────────────────────────────────────────────────────────
echo ""
echo "========================================"
printf "\033[36m  Log Analytics - Startup Script\033[0m\n"
echo "========================================"

# ── Prerequisite checks ───────────────────────────────────────────
if [ "$FRONTEND_ONLY" = false ]; then
    step "Checking Python..."
    if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
        fail "Python not found. Install Python >= 3.11."
        exit 1
    fi
    PY=$(command -v python3 || command -v python)
    info "$($PY --version 2>&1)"
fi

if [ "$BACKEND_ONLY" = false ]; then
    step "Checking Node.js..."
    if ! command -v node &>/dev/null; then
        fail "Node.js not found. Install Node.js >= 18."
        exit 1
    fi
    info "Node $(node --version 2>&1)"
fi

# ── Backend setup ──────────────────────────────────────────────────
if [ "$FRONTEND_ONLY" = false ]; then
    cd "$BACKEND_DIR"

    # Virtual environment
    if [ ! -d ".venv" ]; then
        step "Creating Python virtual environment..."
        $PY -m venv .venv
    fi

    step "Activating virtual environment..."
    # shellcheck disable=SC1091
    source .venv/bin/activate

    if [ "$SKIP_INSTALL" = false ]; then
        step "Installing backend dependencies..."
        pip install -e ".[dev]" --quiet
        info "Done."
    else
        info "Skipping dependency install (--skip-install)."
    fi

    # .env file
    if [ ! -f ".env" ] && [ -f ".env.example" ]; then
        step "Creating .env from .env.example..."
        cp .env.example .env
        warn ".env created with placeholder values. Edit it or configure via the Settings page."
    fi

    # Start backend
    if [ "$DAEMON" = true ]; then
        step "Starting backend (daemon mode)..."
        log-analytics daemon &
    else
        step "Starting backend (server with reload)..."
        log-analytics serve --reload &
    fi
    BACKEND_PID=$!
    info "Backend PID: $BACKEND_PID → http://localhost:8000"

    cd "$ROOT"
fi

# ── Frontend setup ─────────────────────────────────────────────────
if [ "$BACKEND_ONLY" = false ]; then
    cd "$FRONTEND_DIR"

    if [ "$SKIP_INSTALL" = false ] || [ ! -d "node_modules" ]; then
        step "Installing frontend dependencies..."
        npm install --silent
        info "Done."
    else
        info "Skipping npm install (--skip-install)."
    fi

    step "Starting frontend dev server..."
    npm run dev &
    FRONTEND_PID=$!
    info "Frontend PID: $FRONTEND_PID → http://localhost:5173"

    cd "$ROOT"
fi

# ── Summary ────────────────────────────────────────────────────────
sleep 2
echo ""
printf "\033[32m========================================\033[0m\n"
printf "\033[32m  Log Analytics is running!\033[0m\n"
printf "\033[32m========================================\033[0m\n"
echo ""
[ "$FRONTEND_ONLY" = false ] && echo "  Backend API:   http://localhost:8000"
[ "$BACKEND_ONLY" = false ]  && echo "  Frontend:      http://localhost:5173"
[ "$FRONTEND_ONLY" = false ] && echo "  Health check:  http://localhost:8000/health"
echo "  Settings page: http://localhost:5173/settings"
echo ""
echo "  Press Ctrl+C to stop all servers."
echo ""

# ── Wait ───────────────────────────────────────────────────────────
wait
