#!/bin/sh

# TrueSignal Automated Installer & Provisioner
#
# Usage:
#   curl -fsSL <raw>/install.sh | sh
#   curl -fsSL <raw>/install.sh | TS_NODE_API_KEY=<key> sh -s -- --link <hub>
#
# Options:
#   --version <vX.Y.Z>   Install a specific wizard release.
#   --link <hub-url>     Link this node to a Hub after installing.
#   --api-key <key>      Node API key (prefer the TS_NODE_API_KEY env var:
#                        command-line arguments are visible to every local
#                        user through the process list).
#   --sha256 <hash>      Expected SHA-256 of the wizard binary. When set, the
#                        download must match it in addition to checksums.txt.
#                        checksums.txt comes from the same release as the
#                        binary, so on its own it detects corruption, not
#                        tampering.
set -e

do_install() {
    LINK_URL=""
    API_KEY="${TS_NODE_API_KEY:-}"
    TARGET_VERSION=""
    PINNED_SHA256=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --version|--link|--api-key|--sha256)
                if [ $# -lt 2 ]; then
                    printf 'Error: %s requires a value.\n' "$1" >&2
                    exit 1
                fi
                case "$1" in
                    --version) TARGET_VERSION="$2" ;;
                    --link)    LINK_URL="$2" ;;
                    --api-key) API_KEY="$2" ;;
                    --sha256)  PINNED_SHA256="$2" ;;
                esac
                shift 2
                ;;
            *)
                printf 'Warning: ignoring unknown argument: %s\n' "$1" >&2
                shift 1
                ;;
        esac
    done

    if [ -t 1 ]; then
        RESET=$(printf '\033[0m'); BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m')
        CYAN=$(printf '\033[36m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m')
        RED=$(printf '\033[31m'); MAGENTA=$(printf '\033[35m')
    else
        RESET=""; BOLD=""; DIM=""; CYAN=""; GREEN=""; YELLOW=""; RED=""; MAGENTA=""
    fi

    info() { printf '%s==> %s%s\n' "$CYAN" "$1" "$RESET"; }
    fail() { printf '%s%sError:%s%s %s%s\n' "$RED" "$BOLD" "$RESET" "$RED" "$1" "$RESET" >&2; exit 1; }

    printf '%s%s==> Starting TrueSignal Installation...%s\n' "$CYAN" "$BOLD" "$RESET"

    if [ -n "$PINNED_SHA256" ]; then
        PINNED_SHA256=$(printf '%s' "$PINNED_SHA256" | tr 'A-F' 'a-f')
        case "$PINNED_SHA256" in
            *[!0-9a-f]*) fail "--sha256 must be a 64-character hex digest." ;;
        esac
        [ ${#PINNED_SHA256} -eq 64 ] || fail "--sha256 must be a 64-character hex digest."
    fi

    # Upgrade flow
    if command -v truesignal >/dev/null 2>&1; then
        EXISTING_PATH=$(command -v truesignal)
        printf '%s%s==> Warning:%s%s TrueSignal is already installed at %s%s\n' "$YELLOW" "$BOLD" "$RESET" "$YELLOW" "$EXISTING_PATH" "$RESET"
        printf '%sUpgrading in 3 seconds... (Press CTRL + C to cancel)%s\n' "$DIM" "$RESET"
        sleep 3
    fi

    command -v curl >/dev/null 2>&1 || fail "'curl' is required. Aborting."
    command -v sha256sum >/dev/null 2>&1 || fail "'sha256sum' is required. Aborting."

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)        BIN_ARCH="amd64" ;;
        aarch64|arm64) BIN_ARCH="arm64" ;;
        *) fail "Unsupported architecture ($ARCH)" ;;
    esac

    RELEASES_API="https://api.github.com/repos/mahmoudahmed3132/TrueSignal/releases"

    # Resolve the wizard release
    LATEST_TAG=""
    if [ -n "$TARGET_VERSION" ]; then
        case "$TARGET_VERSION" in
            v*) LATEST_TAG="wizard/$TARGET_VERSION" ;;
            *)  LATEST_TAG="wizard/v$TARGET_VERSION" ;;
        esac
        info "Target version specified: ${BOLD}$LATEST_TAG"
    elif [ -n "$LINK_URL" ]; then
        info "Detecting Hub version compatibility from $LINK_URL..."
        HUB_VER=$(curl -fsS --connect-timeout 5 --max-time 15 "$LINK_URL/api/v2/version" 2>/dev/null | grep -o '"version": *"[^"]*' | sed 's/.*"//' || true)
        if [ -n "$HUB_VER" ]; then
            HUB_MAJOR=$(printf '%s' "$HUB_VER" | sed -E 's/^v?([0-9]+).*/\1/')
            info "Hub major version identified: ${BOLD}v$HUB_MAJOR"
            LATEST_TAG=$(curl -fsS --max-time 30 "$RELEASES_API" 2>/dev/null | grep -o "\"tag_name\": *\"wizard/v$HUB_MAJOR\.[^\"]*" | head -n 1 | sed 's/.*"//' || true)
        fi
    fi

    if [ -z "$LATEST_TAG" ]; then
        info "Fetching latest release info from GitHub..."
        LATEST_TAG=$(curl -fsS --max-time 30 "$RELEASES_API" 2>/dev/null | grep -o '"tag_name": *"wizard/[^"]*' | head -n 1 | sed 's/.*"//' || true)
    fi

    [ -n "$LATEST_TAG" ] || fail "Could not determine the Wizard release version from GitHub. Aborting."

    case "$LATEST_TAG" in
        wizard/v[0-9]*) ;;
        *) fail "Refusing unexpected release tag: $LATEST_TAG" ;;
    esac
    case "$LATEST_TAG" in
        *[!A-Za-z0-9./_-]*) fail "Refusing unexpected release tag: $LATEST_TAG" ;;
    esac

    BASE_URL="https://github.com/mahmoudahmed3132/TrueSignal/releases/download/$LATEST_TAG"
    BINARY_NAME="truesignal-linux-$BIN_ARCH"
    INSTALL_PATH="/usr/local/bin/truesignal"

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT INT TERM
    cd "$TMP_DIR"

    info "Downloading ${BOLD}$LATEST_TAG${RESET}${CYAN}..."
    curl -fsSL --proto '=https' --tlsv1.2 "$BASE_URL/$BINARY_NAME" -o "$BINARY_NAME"

    info "Downloading checksums..."
    curl -fsSL --proto '=https' --tlsv1.2 "$BASE_URL/checksums.txt" -o checksums.txt

    info "Verifying checksum..."
    EXPECTED_HASH=$(awk -v f="$BINARY_NAME" '$2 == f || $2 == "*" f {print $1; exit}' checksums.txt)
    [ -n "$EXPECTED_HASH" ] || fail "Binary not found in checksums.txt! Aborting."

    ACTUAL_HASH=$(sha256sum "$BINARY_NAME" | awk '{print $1}')
    [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ] || fail "Checksum verification failed!"

    if [ -n "$PINNED_SHA256" ]; then
        [ "$ACTUAL_HASH" = "$PINNED_SHA256" ] || fail "Binary does not match the pinned --sha256 value!"
        printf '%s✓ Checksum valid and matches the pinned hash.%s\n' "$GREEN" "$RESET"
    else
        printf '%s✓ Checksum valid.%s %s(Pin with --sha256 to detect a tampered release.)%s\n' "$GREEN" "$RESET" "$DIM" "$RESET"
    fi

    SUDO=""
    if [ "$(id -u)" -ne 0 ]; then
        command -v sudo >/dev/null 2>&1 || fail "Not running as root and 'sudo' is not available."
        SUDO="sudo"
    fi

    info "Installing to $INSTALL_PATH..."
    $SUDO install -m 0755 -o 0 -g 0 "$BINARY_NAME" "$INSTALL_PATH"

    if [ -n "$LINK_URL" ]; then
        printf '\n%s%s==> Provisioning Node...%s\n' "$CYAN" "$BOLD" "$RESET"
        # The script itself arrives on stdin (curl | sh), so the wizard reads
        # prompts from the terminal instead when one is attached.
        STDIN_SRC=/dev/null
        if [ -r /dev/tty ] && (: < /dev/tty) 2>/dev/null; then
            STDIN_SRC=/dev/tty
        fi
        if [ -n "$API_KEY" ]; then
            # Pass the key through the environment, not argv.
            TS_NODE_API_KEY="$API_KEY"
            export TS_NODE_API_KEY
            if [ -n "$SUDO" ]; then
                $SUDO --preserve-env=TS_NODE_API_KEY "$INSTALL_PATH" --link "$LINK_URL" < "$STDIN_SRC"
            else
                "$INSTALL_PATH" --link "$LINK_URL" < "$STDIN_SRC"
            fi
        else
            $SUDO "$INSTALL_PATH" --link "$LINK_URL" < "$STDIN_SRC"
        fi
        printf '\n%s%s==> Node Successfully Deployed!%s\n' "$GREEN" "$BOLD" "$RESET"
    else
        printf '\n%s%s==> Installation Complete!%s\n' "$GREEN" "$BOLD" "$RESET"
        printf 'You can now run the tool by typing: %s%struesignal%s\n\n' "$MAGENTA" "$BOLD" "$RESET"
    fi
}

do_install "$@"
