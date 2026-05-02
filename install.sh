#!/usr/bin/env bash
#
# lockshell installer — one-line install for macOS.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/aryateja2106/lockshell/main/install.sh | bash
#
# What this script does:
#   1. Detects your operating system + CPU architecture.
#   2. Downloads the right pre-built lockshell binary from GitHub Releases.
#   3. Verifies the SHA256 checksum.
#   4. Installs it to ~/.local/bin (no sudo required) or /usr/local/bin (asks).
#   5. Tells you the next step (running 'lockshell setup').
#
# What this script DOES NOT do:
#   - Modify your shell rc files. (We print the export line; you copy it.)
#   - Install Rust, brew, or any package manager.
#   - Touch your system Python, Node, or anything you didn't ask for.
#   - Send any data anywhere. The only network calls are to GitHub Releases.
#
# Source: https://github.com/aryateja2106/lockshell/blob/main/install.sh

set -euo pipefail

# ─── config ────────────────────────────────────────────────────────────────────
REPO="aryateja2106/lockshell"
VERSION="${LOCKSHELL_VERSION:-latest}"
INSTALL_DIR="${LOCKSHELL_INSTALL_DIR:-$HOME/.local/bin}"
BIN_NAME="lockshell"

# ─── pretty output ─────────────────────────────────────────────────────────────
RESET=$'\033[0m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
BLUE=$'\033[34m'

# Disable colors if not a tty or NO_COLOR is set
if [ ! -t 1 ] || [ -n "${NO_COLOR:-}" ]; then
    RESET= BOLD= DIM= RED= GREEN= YELLOW= BLUE=
fi

ok()   { printf "%s✓%s %s\n" "$GREEN" "$RESET" "$*"; }
info() { printf "%s→%s %s\n" "$BLUE" "$RESET" "$*"; }
warn() { printf "%s!%s %s\n" "$YELLOW" "$RESET" "$*" >&2; }
die()  { printf "%s✗%s %s\n" "$RED" "$RESET" "$*" >&2; exit 1; }

# ─── banner ────────────────────────────────────────────────────────────────────
printf "%s\n" "${BOLD}lockshell installer${RESET}"
printf "%s%s%s\n\n" "$DIM" "AI-safe secret broker. Cloud LLMs decide; the local broker resolves and executes." "$RESET"

# ─── 1. detect platform ────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin) OS_TAG="apple-darwin" ;;
    Linux)
        warn "Linux detected. lockshell v0.1 is macOS-only because its vault"
        warn "backend (agent-password) requires Apple Keychain + Touch ID."
        warn ""
        warn "Linux support is planned for v0.5. Track:"
        warn "  https://github.com/${REPO}/issues/1"
        warn ""
        warn "If you want to experiment on Linux today, you can build from source"
        warn "but lockshell will fail to talk to a vault. See:"
        warn "  https://github.com/${REPO}/blob/main/docs/ROADMAP.md"
        die "Aborting: no Linux binary available yet."
        ;;
    MINGW*|MSYS*|CYGWIN*)
        die "Windows not supported. v0.5+ may add Windows Credential Manager. Track: https://github.com/${REPO}/issues"
        ;;
    *) die "Unsupported OS: $OS" ;;
esac

case "$ARCH" in
    arm64|aarch64) ARCH_TAG="aarch64" ;;
    x86_64|amd64)  ARCH_TAG="x86_64" ;;
    *) die "Unsupported architecture: $ARCH (need arm64 or x86_64)" ;;
esac

PLATFORM="${ARCH_TAG}-${OS_TAG}"
ok "Detected platform: ${BOLD}${PLATFORM}${RESET}"

# ─── 2. resolve version ────────────────────────────────────────────────────────
if [ "$VERSION" = "latest" ]; then
    info "Resolving latest release tag from GitHub..."
    if command -v curl >/dev/null 2>&1; then
        VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
            | head -n1)"
    else
        die "curl is required. Install it and re-run."
    fi
    [ -n "$VERSION" ] || die "Could not resolve latest release. Check https://github.com/${REPO}/releases"
fi

# Strip leading 'v' if present
VERSION_NUM="${VERSION#v}"
ok "Installing lockshell ${BOLD}${VERSION_NUM}${RESET}"

# ─── 3. download + verify ──────────────────────────────────────────────────────
TARBALL="lockshell-${VERSION_NUM}-${PLATFORM}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
SUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading ${TARBALL}..."
if ! curl -fsSL "$URL" -o "${TMPDIR}/${TARBALL}"; then
    die "Failed to download ${URL}. Check your internet connection."
fi

info "Downloading SHA256SUMS..."
if ! curl -fsSL "$SUMS_URL" -o "${TMPDIR}/SHA256SUMS"; then
    warn "Could not fetch SHA256SUMS. Skipping checksum verification."
    warn "(This is a slight reduction in security; the download is still over HTTPS.)"
else
    info "Verifying checksum..."
    EXPECTED="$(grep "  ${TARBALL}\$" "${TMPDIR}/SHA256SUMS" | awk '{print $1}')"
    if [ -z "$EXPECTED" ]; then
        die "Could not find checksum for ${TARBALL} in SHA256SUMS"
    fi
    ACTUAL="$(shasum -a 256 "${TMPDIR}/${TARBALL}" | awk '{print $1}')"
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        die "Checksum mismatch! expected ${EXPECTED}, got ${ACTUAL}"
    fi
    ok "Checksum verified."
fi

# ─── 4. install ────────────────────────────────────────────────────────────────
info "Extracting..."
tar -xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"
[ -f "${TMPDIR}/${BIN_NAME}" ] || die "Tarball did not contain ${BIN_NAME} binary"
chmod +x "${TMPDIR}/${BIN_NAME}"

mkdir -p "$INSTALL_DIR"
mv "${TMPDIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
ok "Installed to ${BOLD}${INSTALL_DIR}/${BIN_NAME}${RESET}"

# ─── 5. PATH check ─────────────────────────────────────────────────────────────
if ! echo ":$PATH:" | grep -q ":${INSTALL_DIR}:"; then
    printf "\n%s\n" "${YELLOW}⚠  ${INSTALL_DIR} is not in your PATH.${RESET}"
    printf "Add this line to your shell config (%s%s%s, %s%s%s, or %s%s%s):\n\n" \
        "$BOLD" "~/.zshrc" "$RESET" \
        "$BOLD" "~/.bashrc" "$RESET" \
        "$BOLD" "~/.profile" "$RESET"
    printf "  %sexport PATH=\"%s:\$PATH\"%s\n\n" "$BOLD" "$INSTALL_DIR" "$RESET"
    printf "Then reload your shell: %ssource ~/.zshrc%s (or open a new terminal).\n\n" "$BOLD" "$RESET"
fi

# ─── 6. dependency check (agent-password) ──────────────────────────────────────
printf "\n%s\n" "${BOLD}Checking dependencies...${RESET}"

if command -v agent-password >/dev/null 2>&1; then
    ok "agent-password is installed at $(command -v agent-password)"
else
    warn "agent-password is not installed. lockshell needs it as a vault backend."
    warn ""
    warn "To install it (one-time):"
    warn ""
    warn "  ${BOLD}1. Install Rust if needed:${RESET}"
    warn "     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    warn ""
    warn "  ${BOLD}2. Install agent-password:${RESET}"
    warn "     cargo install --git https://github.com/tartavull/agent-password agent-password"
    warn ""
    warn "  ${BOLD}3. Initialize the vault (one-time):${RESET}"
    warn "     agent-password vault init"
    warn ""
    warn "  ${BOLD}4. Then re-run:${RESET} lockshell setup"
fi

# ─── 7. next step ──────────────────────────────────────────────────────────────
printf "\n%s\n" "${GREEN}${BOLD}lockshell installed successfully.${RESET}"
printf "\nNext step:\n"
printf "  %s%s setup%s   ← interactive first-time setup wizard\n" "$BOLD" "${INSTALL_DIR}/${BIN_NAME}" "$RESET"
printf "\nQuick references:\n"
printf "  %s%s --help%s          show all commands\n" "$BOLD" "${BIN_NAME}" "$RESET"
printf "  %s%s doctor%s          diagnose your setup\n" "$BOLD" "${BIN_NAME}" "$RESET"
printf "  %s%s help-me%s         step-by-step beginner guide\n" "$BOLD" "${BIN_NAME}" "$RESET"
printf "\nDocs: %shttps://github.com/%s%s\n" "$BOLD" "$REPO" "$RESET"
printf "\n"
