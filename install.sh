#!/usr/bin/env sh
set -e

# secretfence installer
# Usage: curl -sSL https://raw.githubusercontent.com/solhosty/secretfence/main/install.sh | sh

REPO="solhosty/secretfence"
BINARY="sf"
INSTALL_DIR="/usr/local/bin"

main() {
    platform=$(detect_platform)
    arch=$(detect_arch)
    target="${platform}-${arch}"

    echo "secretfence installer"
    echo "  Platform: ${platform}"
    echo "  Arch:     ${arch}"
    echo "  Target:   ${target}"
    echo ""

    # Get latest release tag
    tag=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')

    if [ -z "$tag" ]; then
        echo "Error: Could not determine latest release."
        echo "Visit https://github.com/${REPO}/releases to download manually."
        exit 1
    fi

    echo "  Version:  v${tag}"

    artifact="secretfence-v${tag}-${target}"
    url="https://github.com/${REPO}/releases/download/v${tag}/${artifact}.tar.gz"

    echo "  URL:      ${url}"
    echo ""

    tmpdir=$(mktemp -d)
    trap "rm -rf ${tmpdir}" EXIT

    echo "Downloading..."
    curl -sSL "${url}" -o "${tmpdir}/secretfence.tar.gz"

    echo "Extracting..."
    tar -xzf "${tmpdir}/secretfence.tar.gz" -C "${tmpdir}"

    echo "Installing to ${INSTALL_DIR}/${BINARY}..."

    if [ -w "${INSTALL_DIR}" ]; then
        cp "${tmpdir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
        chmod +x "${INSTALL_DIR}/${BINARY}"
    else
        echo "Need sudo to install to ${INSTALL_DIR}"
        sudo cp "${tmpdir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY}"
    fi

    echo ""
    echo "secretfence installed successfully!"
    echo ""
    echo "  Run 'sf scan' to get started."
    echo "  Run 'sf --help' for all commands."
    echo ""
}

detect_platform() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *)
            echo "Error: Unsupported platform $(uname -s)" >&2
            exit 1
            ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "x86_64" ;;
        arm64|aarch64) echo "aarch64" ;;
        *)
            echo "Error: Unsupported architecture $(uname -m)" >&2
            exit 1
            ;;
    esac
}

main
