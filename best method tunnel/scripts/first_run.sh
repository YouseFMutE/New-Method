#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DEFAULT="/usr/local/bin/mytunnel"
CONFIG_DIR="/etc/mytunnel"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
SERVICE_FILE="/etc/systemd/system/mytunnel.service"
TEMPLATE_DIR="$ROOT_DIR/configs"
LOG_DIR="/var/log/mytunnel"
LOG_FILE="$LOG_DIR/mytunnel.log"

if [[ -f "$ROOT_DIR/Cargo.toml" ]]; then
  SRC_DIR="$ROOT_DIR"
else
  read -r -p "Path to project root (Cargo.toml): " SRC_DIR
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found, installing Rust toolchain..."
  apt-get update -y
  apt-get install -y curl build-essential pkg-config
  curl -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck source=/root/.cargo/env
  source /root/.cargo/env
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo still not available after install"
  exit 1
fi

if [[ ! -f "$SRC_DIR/Cargo.toml" ]]; then
  echo "Cargo.toml not found in $SRC_DIR"
  exit 1
fi

echo "Building mytunnel..."
cargo build --release --manifest-path "$SRC_DIR/Cargo.toml"

BIN_PATH="$BIN_DEFAULT"
install -m 0755 "$SRC_DIR/target/release/mytunnel" "$BIN_PATH"

mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 0644 "$LOG_FILE"
if [[ -f "$CONFIG_FILE" ]]; then
  echo "Config already exists at $CONFIG_FILE"
else
  case "${CONFIG_TEMPLATE:-}" in
    server)
      cp "$TEMPLATE_DIR/server.example.toml" "$CONFIG_FILE"
      echo "Copied server template to $CONFIG_FILE"
      ;;
    client)
      cp "$TEMPLATE_DIR/client.example.toml" "$CONFIG_FILE"
      echo "Copied client template to $CONFIG_FILE"
      ;;
    *)
      "$BIN_PATH" init --config "$CONFIG_FILE"
      ;;
  esac
fi

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=MyTunnel
After=network.target

[Service]
ExecStart=$BIN_PATH run --config $CONFIG_FILE
Restart=always
RestartSec=3
LimitNOFILE=1048576
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE
SyslogIdentifier=mytunnel

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now mytunnel
systemctl status --no-pager mytunnel
