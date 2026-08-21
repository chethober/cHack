#!/usr/bin/env bash
# ==============================================================================
# cHack - Automated VPS One-Liner Installer
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "======================================================"
echo "          cHack VPS Installation Script               "
echo "======================================================"
echo -e "${NC}"

log_info() { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# 1. Check Root / Sudo
SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        log_warn "Running as non-root without sudo. Some system package installations might fail."
    fi
fi

# 2. Install System Dependencies
log_info "Updating system packages and installing dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -y
    $SUDO apt-get install -y curl wget git jq whois python3 python3-pip nmap libpcap-dev build-essential tar gzip unzip
elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y curl wget git jq whois python3 python3-pip nmap libpcap-devel gcc tar gzip unzip
elif command -v yum >/dev/null 2>&1; then
    $SUDO yum install -y curl wget git jq whois python3 python3-pip nmap libpcap-devel gcc tar gzip unzip
elif command -v pacman >/dev/null 2>&1; then
    $SUDO pacman -Sy --noconfirm curl wget git jq whois python python-pip nmap libpcap base-devel tar gzip unzip
else
    log_warn "Unrecognized package manager. Please ensure git, curl, jq, python3, nmap, and libpcap are installed."
fi

# 3. Setup Go Environment
GO_VERSION="1.23.6"
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) GO_ARCH="amd64" ;;
    aarch64|arm64) GO_ARCH="arm64" ;;
    armv7l) GO_ARCH="armv6l" ;;
    *) GO_ARCH="amd64" ;;
esac

NEED_GO=false
if ! command -v go >/dev/null 2>&1; then
    NEED_GO=true
else
    CURRENT_GO_VER=$(go version | awk '{print $3}' | sed 's/go//')
    # Compare versions: require at least 1.22
    MAJOR=$(echo "$CURRENT_GO_VER" | cut -d. -f1)
    MINOR=$(echo "$CURRENT_GO_VER" | cut -d. -f2)
    if [ "$MAJOR" -lt 1 ] || { [ "$MAJOR" -eq 1 ] && [ "$MINOR" -lt 22 ]; }; then
        log_warn "Installed Go version ($CURRENT_GO_VER) is older than 1.22. Upgrading..."
        NEED_GO=true
    fi
fi

if [ "$NEED_GO" = true ]; then
    log_info "Installing Go v${GO_VERSION} (${GO_ARCH})..."
    GO_TAR="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    wget -q "https://go.dev/dl/${GO_TAR}" -O "/tmp/${GO_TAR}"
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm -f "/tmp/${GO_TAR}"
    log_success "Go installed successfully to /usr/local/go"
fi

# Configure PATH environment
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Persist environment to shell configuration files
for rcfile in "$HOME/.bashrc" "$HOME/.profile" "$HOME/.zshrc"; do
    if [ -f "$rcfile" ]; then
        if ! grep -q "/usr/local/go/bin" "$rcfile"; then
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$rcfile"
        fi
    fi
done

# 4. Install Reconnaissance Tools
log_info "Installing & updating Go reconnaissance tools..."

TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/PentestPad/subzy@latest"
    "github.com/sensepost/gowitness@latest"
)

for pkg in "${TOOLS[@]}"; do
    tool_name=$(basename "$pkg" | cut -d@ -f1)
    log_info "Installing $tool_name..."
    go install -v "$pkg" >/dev/null 2>&1 || log_warn "Failed to install $tool_name (non-critical)"
done

# 5. Initialize Nuclei Templates
if command -v nuclei >/dev/null 2>&1; then
    log_info "Updating Nuclei templates..."
    nuclei -update-templates -silent >/dev/null 2>&1 || true
fi

# 6. Setup cHack Permissions and Environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/cHack.sh" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/js_secrets.py" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/install.sh" 2>/dev/null || true

if [ ! -f "$SCRIPT_DIR/.env" ] && [ -f "$SCRIPT_DIR/.env.example" ]; then
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    log_info "Created .env from .env.example"
fi

echo ""
echo -e "${GREEN}${BOLD}======================================================"
echo -e "         cHack Installation Completed!                "
echo -e "======================================================${NC}"
echo ""
echo -e "To reload environment variables in current shell, run:"
echo -e "  ${CYAN}source ~/.bashrc${NC}  (or source ~/.zshrc / ~/.profile)"
echo ""
echo -e "To start cHack:"
echo -e "  ${CYAN}cd $SCRIPT_DIR${NC}"
echo -e "  ${CYAN}./cHack.sh -i${NC}          # Interactive TUI"
echo -e "  ${CYAN}./cHack.sh -d target.com${NC} # Full scan"
echo -e "  ${CYAN}./cHack.sh --daemon${NC}      # Background runner"
echo ""
