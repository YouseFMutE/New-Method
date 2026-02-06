#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

REPO_URL="${REPO_URL:-REPLACE_WITH_GIT_URL}"
INSTALL_DIR="${INSTALL_DIR:-/opt/mytunnel}"
CONFIG_TEMPLATE="${CONFIG_TEMPLATE:-}"

apt-get update -y
apt-get install -y curl git build-essential pkg-config

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found, installing Rust toolchain..."
  curl -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck source=/root/.cargo/env
  source /root/.cargo/env
fi

if [[ "$REPO_URL" == "REPLACE_WITH_GIT_URL" ]]; then
  echo "REPO_URL is not set. Example:"
  echo "  REPO_URL=https://github.com/yourname/mytunnel.git bash <(curl -fsSL https://yourdomain/install.sh)"
  exit 1
fi

if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" pull --rebase
else
  rm -rf "$INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

CONFIG_TEMPLATE="$CONFIG_TEMPLATE" bash "$INSTALL_DIR/scripts/first_run.sh"
