#!/usr/bin/env bash
# ReconForge installer — macOS, Ubuntu/Debian, Kali Linux.
#
#   ./install.sh                 # app + all recon tools + PATH setup
#   ./install.sh --app-only      # Python app and dashboard only
#   ./install.sh --tools-only    # recon tools only (app already installed)
#   ./install.sh --no-shell-rc   # don't touch ~/.zshrc / ~/.bashrc
#   ./install.sh --skip "amass trufflehog"   # skip specific tools
#   ./install.sh --only nuclei   # install one tool only (used by the dashboard Install button)
#   ./install.sh --yes           # non-interactive (assume yes for package-manager prompts)
#
# For every tool: if a working copy already exists (PATH, ~/go/bin, Homebrew, /usr/local/bin, ...),
# it is reused; otherwise it is installed (Homebrew / apt / go install / release binary / pip / npm).
# At the end `reconforge tools --detect` verifies each binary (e.g. ProjectDiscovery httpx, not the
# Python httpx client) and records absolute paths in ~/.reconforge/tool-paths.yaml, which ReconForge
# loads automatically — no runtime PATH guessing.
set -o pipefail   # no -u: macOS bash 3.2 treats empty arrays as unbound

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP=1; TOOLS=1; SHELLRC=1; YES=""; SKIP=""; ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --app-only) TOOLS=0 ;;
    --tools-only) APP=0 ;;
    --no-shell-rc) SHELLRC=0 ;;
    --skip) SKIP="$2"; shift ;;
    --only) ONLY="$2"; shift ;;   # install just one tool (used by the dashboard Install button)
    --yes|-y) YES="-y" ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
  shift
done
[[ -n "$ONLY" ]] && { APP=0; SHELLRC=0; }

c_ok=$'\e[32m'; c_warn=$'\e[33m'; c_err=$'\e[31m'; c_dim=$'\e[2m'; c_b=$'\e[1m'; c_0=$'\e[0m'
say()  { printf '%s==>%s %s\n' "$c_b" "$c_0" "$*"; }
ok()   { printf '  %s✓%s %s\n' "$c_ok" "$c_0" "$*"; }
warn() { printf '  %s!%s %s\n' "$c_warn" "$c_0" "$*"; }
err()  { printf '  %s✗%s %s\n' "$c_err" "$c_0" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
skip() { [[ " $SKIP " == *" $1 "* ]]; }

INSTALLED=(); REUSED=(); FAILED=()
LOG="${TMPDIR:-/tmp}/reconforge-install-$$.log"
: > "$LOG"

# ------------------------------------------------------------------ platform
OS="$(uname -s)"; ARCH="$(uname -m)"; DISTRO=""
if [[ "$OS" == "Linux" && -r /etc/os-release ]]; then . /etc/os-release; DISTRO="${ID:-linux}"; fi
case "$OS" in
  Darwin) PLATFORM="macos" ;;
  Linux)  case "$DISTRO" in ubuntu|debian|kali|linuxmint|pop|parrot) PLATFORM="debian" ;; *) PLATFORM="linux" ;; esac ;;
  *) echo "Unsupported OS: $OS (supported: macOS, Ubuntu/Debian, Kali)"; exit 1 ;;
esac
SUDO=""; [[ "$PLATFORM" != "macos" && $EUID -ne 0 ]] && SUDO="sudo"
GOARCH="amd64"; [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]] && GOARCH="arm64"
SHARE="$HOME/.local/share/reconforge"; mkdir -p "$SHARE/bin" "$HOME/.local/bin"
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin:$SHARE/bin:$HOME/.local/go/bin:/usr/local/go/bin"
[[ -x /opt/homebrew/bin/brew ]] && eval "$(/opt/homebrew/bin/brew shellenv)"
say "Platform: $PLATFORM ($OS ${DISTRO:+$DISTRO }$ARCH)   log: $LOG"

# --------------------------------------------------------------- base packages
brew_install() { brew list --formula "$1" >/dev/null 2>&1 || brew install "$1" >>"$LOG" 2>&1; }
apt_updated=0
apt_install() {
  if [[ $apt_updated -eq 0 ]]; then $SUDO apt-get update $YES >>"$LOG" 2>&1; apt_updated=1; fi
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y --no-install-recommends "$@" >>"$LOG" 2>&1
}

base_packages() {
  say "Base packages"
  if [[ "$PLATFORM" == "macos" ]]; then
    if ! have brew; then
      err "Homebrew is required on macOS: https://brew.sh  (then re-run ./install.sh)"; exit 1
    fi
    for p in python@3.12 node libpcap; do brew_install "$p" && ok "$p" || warn "$p (see log)"; done
  elif [[ "$PLATFORM" == "debian" ]]; then
    apt_install python3 python3-venv python3-pip git curl unzip ca-certificates build-essential libpcap-dev nodejs npm \
      && ok "python3, venv, git, curl, build tools, libpcap, node" || warn "some base packages failed (see log)"
  else
    warn "unknown Linux distribution: install python3, venv, git, curl, unzip, libpcap-dev, nodejs/npm manually"
  fi
}

# ------------------------------------------------------------------- Go toolchain
go_ok() { have go && go version 2>/dev/null | awk '{print $3}' | sed 's/go//' | awk -F. '{exit !($1>1 || ($1==1 && $2>=22))}'; }
ensure_go() {
  go_ok && { ok "go $(go version | awk '{print $3}')"; return 0; }
  if [[ "$PLATFORM" == "macos" ]]; then brew_install go
  else
    local v; v="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)"
    [[ -n "$v" ]] || { err "could not determine latest Go version"; return 1; }
    curl -fsSL "https://go.dev/dl/${v}.linux-${GOARCH}.tar.gz" -o "$SHARE/go.tgz" >>"$LOG" 2>&1 \
      && rm -rf "$HOME/.local/go" && tar -C "$HOME/.local" -xzf "$SHARE/go.tgz" && rm -f "$SHARE/go.tgz"
  fi
  go_ok && ok "go $(go version | awk '{print $3}') installed" || { err "Go installation failed"; return 1; }
}

# ---------------------------------------------------------------------- tools
# name | go package | brew formula | apt package | verify-args | signature
TOOLS_TABLE='
subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|||-version|projectdiscovery|current version|engine version
dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest|||-version|projectdiscovery|current version|engine version
httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest|||-version|projectdiscovery|current version|engine version
tlsx|github.com/projectdiscovery/tlsx/cmd/tlsx@latest|||-version|projectdiscovery|current version|engine version
katana|github.com/projectdiscovery/katana/cmd/katana@latest|||-version|projectdiscovery|current version|engine version
nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest|||-version|projectdiscovery|current version|engine version
naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest|||-version|projectdiscovery|current version|engine version
chaos|github.com/projectdiscovery/chaos-client/cmd/chaos@latest|||-version|projectdiscovery|current version|engine version
shuffledns|github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest|||-version|projectdiscovery|current version|engine version
amass|github.com/owasp-amass/amass/v4/...@master|amass|amass|-version|
assetfinder|github.com/tomnomnom/assetfinder@latest|||-h|
waybackurls|github.com/tomnomnom/waybackurls@latest|||-h|
gau|github.com/lc/gau/v2/cmd/gau@latest|||--version|
puredns|github.com/d3mondev/puredns/v2@latest|||--version|puredns
github-subdomains|github.com/gwen001/github-subdomains@latest|||-h|
gitleaks|github.com/zricethezav/gitleaks/v8@latest|gitleaks||version|
trufflehog|github.com/trufflesecurity/trufflehog/v3@latest|trufflehog||--version|
nmap||nmap|nmap|--version|nmap
sslscan||sslscan|sslscan|--version|sslscan|openssl
massdns||massdns|massdns|--help|
whatweb||whatweb|whatweb|--version|whatweb
findomain||findomain||--version|findomain
ffuf|github.com/ffuf/ffuf/v2@latest|ffuf||-V|ffuf
gobuster|github.com/OJ/gobuster/v3@latest|gobuster|gobuster|version|
feroxbuster||feroxbuster||-V|feroxbuster
dirb|||dirb||
'

find_existing() {  # $1=name $2=args $3=signature -> prints path of a working binary
  local name="$1" args="$2" sig="$3" d
  for d in $(echo "$PATH" | tr ':' ' ') "$GOPATH/bin" "$HOME/.local/bin" "$SHARE/bin" /opt/homebrew/bin /usr/local/bin /usr/bin /snap/bin; do
    if [[ -x "$d/$name" && ! -d "$d/$name" ]]; then
      [[ -z "$sig" ]] && { echo "$d/$name"; return 0; }
      local out; out="$("$d/$name" $args 2>&1 </dev/null | head -60)"
      if grep -qiE "$sig" <<< "$out"; then echo "$d/$name"; return 0; fi
    fi
  done
  return 1
}

install_findomain_release() {
  local asset="findomain-linux.zip"; [[ "$GOARCH" == "arm64" ]] && asset="findomain-aarch64.zip"
  curl -fsSL "https://github.com/Findomain/Findomain/releases/latest/download/$asset" -o "$SHARE/fd.zip" >>"$LOG" 2>&1 \
    && unzip -o -q "$SHARE/fd.zip" -d "$SHARE/bin" && chmod +x "$SHARE/bin/findomain" && rm -f "$SHARE/fd.zip"
}

install_whatweb_source() {  # WhatWeb is not in Homebrew; build from the official repository
  local ruby_bin=""
  if [[ "$PLATFORM" == "macos" ]]; then brew_install ruby || return 1; ruby_bin="$(brew --prefix ruby)/bin"; fi
  [[ -n "$ruby_bin" ]] && export PATH="$ruby_bin:$PATH"
  have ruby || return 1
  if [[ -d "$SHARE/WhatWeb/.git" ]]; then git -C "$SHARE/WhatWeb" pull -q >>"$LOG" 2>&1
  else git clone -q --depth 1 https://github.com/urbanadventurer/WhatWeb "$SHARE/WhatWeb" >>"$LOG" 2>&1 || return 1; fi
  (cd "$SHARE/WhatWeb" && bundle config set --local path vendor/bundle >>"$LOG" 2>&1 && bundle install >>"$LOG" 2>&1) || return 1
  {
    echo '#!/bin/sh'
    [[ -n "$ruby_bin" ]] && echo "export PATH=\"$ruby_bin:\$PATH\""
    echo "export BUNDLE_GEMFILE=\"$SHARE/WhatWeb/Gemfile\""
    echo "exec ruby -rbundler/setup \"$SHARE/WhatWeb/whatweb\" \"\$@\""
  } > "$SHARE/bin/whatweb"
  chmod +x "$SHARE/bin/whatweb"
}

install_tool() {  # name gopkg brew apt args sig
  local name="$1" gopkg="$2" brewf="$3" aptp="$4" args="$5" sig="$6" p
  skip "$name" && { warn "$name skipped (--skip)"; return; }
  if p="$(find_existing "$name" "$args" "$sig")"; then REUSED+=("$name"); ok "$name already present: $p"; return; fi
  printf '  … %s installing' "$name"
  local rc=1
  if [[ "$PLATFORM" == "macos" && -n "$brewf" ]]; then brew_install "$brewf" && rc=0
  elif [[ "$PLATFORM" == "debian" && -n "$aptp" ]]; then apt_install "$aptp" && rc=0
  fi
  if [[ $rc -ne 0 && -n "$gopkg" ]] && have go; then
    CGO_ENABLED=1 go install -v "$gopkg" >>"$LOG" 2>&1 && rc=0
  fi
  if [[ $rc -ne 0 && "$name" == "findomain" && "$PLATFORM" != "macos" ]]; then install_findomain_release && rc=0; fi
  if [[ $rc -ne 0 && "$name" == "whatweb" ]]; then install_whatweb_source && rc=0; fi
  if [[ $rc -ne 0 && "$name" == "massdns" ]]; then  # build from source when no package exists
    (cd "$SHARE" && rm -rf massdns-src && git clone -q --depth 1 https://github.com/blechschmidt/massdns massdns-src \
      && make -C massdns-src >>"$LOG" 2>&1 && cp massdns-src/bin/massdns "$SHARE/bin/") && rc=0
  fi
  printf '\r'
  if [[ $rc -eq 0 ]] && p="$(find_existing "$name" "$args" "$sig")"; then INSTALLED+=("$name"); ok "$name installed: $p"
  else FAILED+=("$name"); err "$name could not be installed (see $LOG)"; fi
}

dirsearch_tool() {
  skip dirsearch && return
  if find_existing dirsearch --version "" >/dev/null; then REUSED+=("dirsearch"); ok "dirsearch already present"; return; fi
  if [[ -x "$ROOT/.venv/bin/pip" ]] && "$ROOT/.venv/bin/pip" install -q dirsearch >>"$LOG" 2>&1; then
    ln -sf "$ROOT/.venv/bin/dirsearch" "$SHARE/bin/dirsearch"; INSTALLED+=("dirsearch"); ok "dirsearch installed (app venv)"
  else FAILED+=("dirsearch"); err "dirsearch (see log)"; fi
}

python_tools() {
  dirsearch_tool
  skip waymore && return
  if find_existing waymore --version "" >/dev/null; then REUSED+=("waymore"); ok "waymore already present"; return; fi
  if [[ -x "$ROOT/.venv/bin/pip" ]] && "$ROOT/.venv/bin/pip" install -q waymore >>"$LOG" 2>&1; then
    ln -sf "$ROOT/.venv/bin/waymore" "$SHARE/bin/waymore"; INSTALLED+=("waymore"); ok "waymore installed (app venv)"
  else FAILED+=("waymore"); err "waymore (see log)"; fi
}

node_tools() {
  skip retire && return
  if find_existing retire --version "" >/dev/null; then REUSED+=("retire"); ok "retire already present"; return; fi
  if have npm && npm install --prefix "$SHARE/npm" retire >>"$LOG" 2>&1; then
    ln -sf "$SHARE/npm/node_modules/.bin/retire" "$SHARE/bin/retire"; INSTALLED+=("retire"); ok "retire installed"
  else FAILED+=("retire"); err "retire (needs node/npm; see log)"; fi
}

browser() {
  skip chrome && return
  if [[ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" || -x "/Applications/Chromium.app/Contents/MacOS/Chromium" ]] \
     || have google-chrome || have google-chrome-stable || have chromium || have chromium-browser; then
    REUSED+=("chrome"); ok "Chrome/Chromium present (screenshots)"; return
  fi
  if [[ "$PLATFORM" == "macos" ]]; then brew install --cask chromium >>"$LOG" 2>&1 && { INSTALLED+=("chromium"); ok "chromium installed"; } || warn "chromium (optional; screenshots)"
  elif [[ "$PLATFORM" == "debian" ]]; then (apt_install chromium || apt_install chromium-browser) && { INSTALLED+=("chromium"); ok "chromium installed"; } || warn "chromium (optional; screenshots)"
  fi
}

# --------------------------------------------------------------------- the app
install_app() {
  say "ReconForge application"
  local py=""
  for c in python3.13 python3.12 python3.11 python3.10 python3; do
    if have "$c" && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then py="$c"; break; fi
  done
  [[ -n "$py" ]] || { err "Python >= 3.10 not found"; exit 1; }
  [[ -d "$ROOT/.venv" ]] || "$py" -m venv "$ROOT/.venv"
  "$ROOT/.venv/bin/pip" install -q --upgrade pip >>"$LOG" 2>&1
  if "$ROOT/.venv/bin/pip" install -q -e "$ROOT[ai,dev]" >>"$LOG" 2>&1; then ok "python package + dependencies ($("$ROOT/.venv/bin/python" -V))"
  else err "pip install failed (see $LOG)"; exit 1; fi
  if [[ ! -f "$ROOT/reconforge/api/static/index.html" ]] && have npm; then
    (cd "$ROOT/frontend" && npm install --no-audit --no-fund >>"$LOG" 2>&1 && npm run build >>"$LOG" 2>&1) && ok "dashboard built" || warn "dashboard build failed"
  else ok "dashboard bundle present"
  fi
  ln -sf "$ROOT/.venv/bin/reconforge" "$HOME/.local/bin/reconforge" && ok "launcher: ~/.local/bin/reconforge"
  if [[ ! -f "$ROOT/config/reconforge.yaml" && -f "$ROOT/config/reconforge.example.yaml" ]]; then
    cp "$ROOT/config/reconforge.example.yaml" "$ROOT/config/reconforge.yaml" && ok "config/reconforge.yaml created from the example (git-ignored)"
  fi
}

shell_rc() {
  [[ $SHELLRC -eq 1 ]] || return
  local line='export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.local/share/reconforge/bin:$HOME/.local/go/bin"'
  local rc files=()
  [[ -f "$HOME/.zshrc" || "${SHELL:-}" == *zsh ]] && files+=("$HOME/.zshrc")
  [[ -f "$HOME/.bashrc" || "${SHELL:-}" == *bash ]] && files+=("$HOME/.bashrc")
  for rc in "${files[@]}"; do
    touch "$rc"
    if ! grep -q '# >>> reconforge >>>' "$rc"; then
      printf '\n# >>> reconforge >>>\n%s\n# <<< reconforge <<<\n' "$line" >> "$rc"; ok "PATH updated in $rc"
    else ok "PATH already configured in $rc"; fi
  done
}

install_one() {  # install a single named tool (table row, or a pseudo-tool), then re-detect
  local want="$1" row
  ensure_go >/dev/null 2>&1 || true
  case "$want" in
    waymore) python_tools; return ;;
    dirsearch) dirsearch_tool; return ;;
    retire) node_tools; return ;;
    chrome|chromium) browser; return ;;
    nuclei-templates)
      local nb; nb="$(command -v nuclei || echo "$GOPATH/bin/nuclei")"
      [[ -x "$nb" ]] && "$nb" -update-templates -silent >>"$LOG" 2>&1 && ok "nuclei templates updated" || err "need nuclei first"
      return ;;
  esac
  while IFS='|' read -r n g b a args sig; do
    [[ "$n" == "$want" ]] || continue
    install_tool "$n" "$g" "$b" "$a" "$args" "$sig" </dev/null; return
  done <<< "$TOOLS_TABLE"
  err "unknown tool: $want"; return 1
}

# ----------------------------------------------------------------------- run
if [[ -n "$ONLY" ]]; then
  say "Installing $ONLY"
  install_one "$ONLY"
  say "Recording tool paths"
  [[ -x "$ROOT/.venv/bin/reconforge" ]] && "$ROOT/.venv/bin/reconforge" tools --detect >/dev/null 2>&1
  [[ ${#INSTALLED[@]} -gt 0 ]] && { echo "installed: ${INSTALLED[*]}"; exit 0; }
  [[ ${#REUSED[@]} -gt 0 ]] && { echo "already present: ${REUSED[*]}"; exit 0; }
  echo "failed: ${FAILED[*]:-$ONLY} (details: $LOG)"; exit 1
fi

[[ $APP -eq 1 && $TOOLS -eq 1 ]] && base_packages
[[ $APP -eq 1 ]] && install_app
if [[ $TOOLS -eq 1 ]]; then
  [[ $APP -eq 0 ]] && base_packages
  say "Go toolchain"; ensure_go
  say "Recon tools"
  while IFS='|' read -r n g b a args sig; do
    [[ -z "$n" ]] && continue
    install_tool "$n" "$g" "$b" "$a" "$args" "$sig" </dev/null   # brew/go must not eat the table on stdin
  done <<< "$TOOLS_TABLE"
  python_tools; node_tools; browser
  if have nuclei || [[ -x "$GOPATH/bin/nuclei" ]]; then
    say "Nuclei templates"; ("$(command -v nuclei || echo "$GOPATH/bin/nuclei")" -update-templates -silent >>"$LOG" 2>&1) \
      || warn "template update failed"
  fi
fi
shell_rc

say "Verifying tools and recording absolute paths"
if [[ -x "$ROOT/.venv/bin/reconforge" ]]; then "$ROOT/.venv/bin/reconforge" tools --detect | grep -E '^  (OK|BAD)|^wrote'; fi

say "Summary"
[[ ${#INSTALLED[@]} -gt 0 ]] && echo "  installed: ${INSTALLED[*]}"
[[ ${#REUSED[@]} -gt 0 ]] && echo "  reused:    ${REUSED[*]}"
[[ ${#FAILED[@]} -gt 0 ]] && echo "  ${c_err}failed:    ${FAILED[*]}${c_0}   (details: $LOG)"
echo
echo "  Start the dashboard:  ${c_b}reconforge${c_0}     (open a new terminal first so PATH changes apply)"
echo "  Re-check tools later: reconforge tools --detect"
