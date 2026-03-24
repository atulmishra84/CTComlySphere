#!/usr/bin/env bash
# =============================================================================
# CT ComplySphere Collector Agent — Install Script
# =============================================================================
# Usage:
#   curl -fsSL https://your-platform/static/agent/install.sh | bash -s -- \
#       --token YOUR_API_TOKEN \
#       --platform https://your-platform-url
#
# Or download and run locally:
#   chmod +x install.sh
#   ./install.sh --token YOUR_TOKEN --platform https://your-platform
# =============================================================================
set -euo pipefail

AGENT_VERSION="1.0.0"
INSTALL_DIR="${INSTALL_DIR:-/opt/complysphere-agent}"
SERVICE_NAME="complysphere-agent"
PYTHON_MIN="3.8"

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Parse arguments ─────────────────────────────────────────────────────────
PLATFORM_URL=""
API_TOKEN=""
SCAN_INTERVAL="${SCAN_INTERVAL:-3600}"
ENABLED_SCANNERS="${ENABLED_SCANNERS:-}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
USE_DOCKER=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)    PLATFORM_URL="$2";    shift 2 ;;
    --token)       API_TOKEN="$2";       shift 2 ;;
    --interval)    SCAN_INTERVAL="$2";   shift 2 ;;
    --scanners)    ENABLED_SCANNERS="$2"; shift 2 ;;
    --docker)      USE_DOCKER=true;      shift   ;;
    --install-dir) INSTALL_DIR="$2";     shift 2 ;;
    -h|--help)
      echo "Usage: $0 --platform URL --token TOKEN [--interval SECS] [--docker]"
      exit 0 ;;
    *) warn "Unknown argument: $1"; shift ;;
  esac
done

[[ -z "$PLATFORM_URL" ]] && error "--platform URL is required"
[[ -z "$API_TOKEN"    ]] && error "--token TOKEN is required"

# ── Banner ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║   CT ComplySphere Collector Agent  v${AGENT_VERSION}       ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${RESET}"
info "Platform : $PLATFORM_URL"
info "Install  : $INSTALL_DIR"
info "Interval : ${SCAN_INTERVAL}s"

# ── Docker path ──────────────────────────────────────────────────────────────
if $USE_DOCKER || command -v docker &>/dev/null; then
  if $USE_DOCKER || { command -v docker &>/dev/null && docker info &>/dev/null 2>&1; }; then
    info "Docker detected — deploying via Docker …"
    docker pull complysphere/collector-agent:latest 2>/dev/null || true

    docker rm -f "$SERVICE_NAME" 2>/dev/null || true
    docker run -d \
      --name "$SERVICE_NAME" \
      --restart unless-stopped \
      -e PLATFORM_URL="$PLATFORM_URL" \
      -e API_TOKEN="$API_TOKEN" \
      -e SCAN_INTERVAL="$SCAN_INTERVAL" \
      -e ENABLED_SCANNERS="$ENABLED_SCANNERS" \
      -e LOG_LEVEL="$LOG_LEVEL" \
      -v /var/run/docker.sock:/var/run/docker.sock:ro \
      complysphere/collector-agent:latest

    success "Agent running as Docker container '$SERVICE_NAME'"
    echo ""
    echo -e "  ${BOLD}View logs:${RESET}  docker logs -f $SERVICE_NAME"
    echo -e "  ${BOLD}Stop:${RESET}       docker stop $SERVICE_NAME"
    echo ""
    exit 0
  fi
fi

# ── Python / pip path ─────────────────────────────────────────────────────────
info "Checking Python …"
PYTHON=""
for py in python3 python; do
  if command -v "$py" &>/dev/null; then
    ver=$($py -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" 2>/dev/null; then
      PYTHON="$py"
      break
    fi
  fi
done
[[ -z "$PYTHON" ]] && error "Python ${PYTHON_MIN}+ is required. Install it and re-run."
success "Found Python: $($PYTHON --version)"

# ── Create install directory ──────────────────────────────────────────────────
info "Creating install directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# ── Download agent files ──────────────────────────────────────────────────────
info "Downloading agent …"
curl -fsSL "${PLATFORM_URL}/static/agent/agent.py"       -o "${INSTALL_DIR}/agent.py"
curl -fsSL "${PLATFORM_URL}/static/agent/requirements.txt" -o "${INSTALL_DIR}/requirements.txt"
success "Agent files downloaded"

# ── Virtual environment ───────────────────────────────────────────────────────
VENV="${INSTALL_DIR}/venv"
if [[ ! -d "$VENV" ]]; then
  info "Creating Python virtual environment …"
  $PYTHON -m venv "$VENV"
fi
"${VENV}/bin/pip" install --quiet --upgrade pip
"${VENV}/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"
success "Dependencies installed"

# ── Write .env file ───────────────────────────────────────────────────────────
cat > "${INSTALL_DIR}/.env" <<ENVEOF
PLATFORM_URL=${PLATFORM_URL}
API_TOKEN=${API_TOKEN}
SCAN_INTERVAL=${SCAN_INTERVAL}
ENABLED_SCANNERS=${ENABLED_SCANNERS}
LOG_LEVEL=${LOG_LEVEL}
ENVEOF
chmod 600 "${INSTALL_DIR}/.env"
success ".env written (chmod 600)"

# ── systemd service ───────────────────────────────────────────────────────────
if command -v systemctl &>/dev/null && [[ "$EUID" -eq 0 ]]; then
  info "Installing systemd service …"
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<SVCEOF
[Unit]
Description=CT ComplySphere Collector Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${VENV}/bin/python agent.py
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable  "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
  success "systemd service '${SERVICE_NAME}' started"
  echo ""
  echo -e "  ${BOLD}View logs:${RESET}  journalctl -u ${SERVICE_NAME} -f"
  echo -e "  ${BOLD}Status:${RESET}     systemctl status ${SERVICE_NAME}"
else
  # Fallback: launch in background with nohup
  info "Starting agent in background (nohup) …"
  set -a; source "${INSTALL_DIR}/.env"; set +a
  nohup "${VENV}/bin/python" "${INSTALL_DIR}/agent.py" \
    >> "${INSTALL_DIR}/agent.log" 2>&1 &
  echo $! > "${INSTALL_DIR}/agent.pid"
  success "Agent started (PID $(cat "${INSTALL_DIR}/agent.pid"))"
  echo ""
  echo -e "  ${BOLD}View logs:${RESET}  tail -f ${INSTALL_DIR}/agent.log"
  echo -e "  ${BOLD}Stop:${RESET}       kill \$(cat ${INSTALL_DIR}/agent.pid)"
fi

echo ""
echo -e "${GREEN}${BOLD}Installation complete!${RESET}"
echo -e "The agent will begin reporting discovered AI agents to ${BLUE}${PLATFORM_URL}${RESET}"
echo ""
