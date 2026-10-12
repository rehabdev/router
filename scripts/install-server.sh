#!/usr/bin/env bash
set -Eeuo pipefail

readonly DEFAULT_REPOSITORY="__ASIRA_ROUTER_REPOSITORY__"
readonly INSTALL_DIR="/usr/local/bin"
readonly CONFIG_DIR="/etc/asira-router"
readonly SERVICE_PATH="/etc/systemd/system/asira-router.service"

repository="${ASIRA_ROUTER_REPOSITORY:-$DEFAULT_REPOSITORY}"
version="${ASIRA_ROUTER_VERSION:-latest}"

usage() {
    cat <<'EOF'
Usage: install-server.sh [--repository OWNER/REPOSITORY] [--version TAG]

Environment equivalents:
  ASIRA_ROUTER_REPOSITORY  GitHub repository, for example asira/router
  ASIRA_ROUTER_VERSION     Release tag, for example v0.1.0 (default: latest)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repository)
            [[ $# -ge 2 ]] || { echo "--repository needs OWNER/REPOSITORY" >&2; exit 2; }
            repository="$2"
            shift 2
            ;;
        --version)
            [[ $# -ge 2 ]] || { echo "--version needs a release tag" >&2; exit 2; }
            version="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$repository" == "__ASIRA_ROUTER_REPOSITORY__" || ! "$repository" =~ ^[^/[:space:]]+/[^/[:space:]]+$ ]]; then
    echo "Set --repository OWNER/REPOSITORY or ASIRA_ROUTER_REPOSITORY before installing." >&2
    exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run this installer with sudo or as root." >&2
    exit 1
fi
for command in curl install sha256sum tar systemctl; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "Required command is missing: $command" >&2
        exit 1
    }
done
if [[ "$(uname -m)" != "x86_64" && "$(uname -m)" != "amd64" ]]; then
    echo "This release currently supports Ubuntu x86_64 only." >&2
    echo "Detected architecture: $(uname -m)" >&2
    exit 1
fi

if [[ "$version" == "latest" ]]; then
    release_base="https://github.com/$repository/releases/latest/download"
else
    release_base="https://github.com/$repository/releases/download/$version"
fi
asset="asira-router-server-linux-x86_64.tar.gz"
temporary_directory="$(mktemp -d)"
cleanup() {
    rm -rf "$temporary_directory"
}
trap cleanup EXIT

echo "Downloading Asira Router server ($version)..."
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --output "$temporary_directory/$asset" "$release_base/$asset"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --output "$temporary_directory/SHA256SUMS" "$release_base/SHA256SUMS"

expected_checksum="$(awk -v asset="$asset" '$2 == asset || $2 == "*" asset { print $1; exit }' "$temporary_directory/SHA256SUMS")"
[[ "$expected_checksum" =~ ^[[:xdigit:]]{64}$ ]] || {
    echo "The release checksum does not contain $asset." >&2
    exit 1
}
actual_checksum="$(sha256sum "$temporary_directory/$asset" | awk '{ print $1 }')"
if [[ "$actual_checksum" != "$expected_checksum" ]]; then
    echo "The downloaded server package failed checksum verification." >&2
    exit 1
fi

mkdir -p "$temporary_directory/package"
tar -xzf "$temporary_directory/$asset" -C "$temporary_directory/package"
[[ -x "$temporary_directory/package/asira-server" ]] || {
    echo "The release package did not contain asira-server." >&2
    exit 1
}
[[ -f "$temporary_directory/package/asira-router.service" ]] || {
    echo "The release package did not contain the systemd service." >&2
    exit 1
}

install -D -m 0755 "$temporary_directory/package/asira-server" "$INSTALL_DIR/asira-server"
install -D -m 0644 "$temporary_directory/package/asira-router.service" "$SERVICE_PATH"
install -d -m 0700 "$CONFIG_DIR"

config_path="$CONFIG_DIR/server.toml"
if [[ ! -f "$config_path" ]]; then
    [[ -f "$temporary_directory/package/server.toml.example" ]] || {
        echo "The release package did not contain server.toml.example." >&2
        exit 1
    }
    cp "$temporary_directory/package/server.toml.example" "$config_path"
    chmod 600 "$config_path"
fi

if grep -q 'replace-this-with-a-long-random-passphrase' "$config_path"; then
    echo
    echo "Create the shared passphrase used by the Windows clients."
    echo "Use at least 16 bytes; a long random passphrase is recommended."
    while true; do
        read -r -s -p "Passphrase: " passphrase
        echo
        read -r -s -p "Repeat passphrase: " repeated_passphrase
        echo
        if [[ -z "$passphrase" || "$passphrase" != "$repeated_passphrase" ]]; then
            echo "The passphrases did not match." >&2
            continue
        fi
        if [[ "${#passphrase}" -lt 16 ]]; then
            echo "The passphrase must be at least 16 bytes." >&2
            continue
        fi
        if [[ "$passphrase" == *'"'* || "$passphrase" == *'\\'* || "$passphrase" == *$'\n'* || "$passphrase" == *$'\r'* ]]; then
            echo 'The passphrase cannot contain quotes, backslashes, or newlines.' >&2
            continue
        fi
        break
    done
    temporary_config="$temporary_directory/server.toml"
    awk -v passphrase="$passphrase" '
        /^passphrase[[:space:]]*=/ { print "passphrase = \"" passphrase "\""; next }
        { print }
    ' "$config_path" > "$temporary_config"
    install -m 0600 "$temporary_config" "$config_path"
fi
chmod 600 "$config_path"

systemctl daemon-reload
systemctl enable asira-router.service >/dev/null
systemctl restart asira-router.service

echo
echo "Asira Router server is installed and running."
echo "Config: $config_path"
echo "Service: asira-router.service"
echo
echo "Before connecting clients, enable IPv4 forwarding and configure NAT/firewall rules."
echo "See the server networking section in DOCS.md for the required nftables setup."
