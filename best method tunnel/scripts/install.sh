#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

REPO_URL="${REPO_URL:-https://github.com/YouseFMutE/New-Method.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/mytunnel}"
PROJECT_SUBDIR="${PROJECT_SUBDIR:-best method tunnel}"
CONFIG_TEMPLATE="${CONFIG_TEMPLATE:-}"

apt-get update -y
apt-get install -y curl git build-essential pkg-config

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found, installing Rust toolchain..."
  curl -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck source=/root/.cargo/env
  source /root/.cargo/env
fi

if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" pull --rebase
else
  rm -rf "$INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
fi

PROJECT_DIR="$INSTALL_DIR/$PROJECT_SUBDIR"
if [[ ! -d "$PROJECT_DIR" ]]; then
  echo "Project subdir not found: $PROJECT_DIR"
  echo "Set PROJECT_SUBDIR to the correct path inside the repo."
  exit 1
fi

CONFIG_TEMPLATE="$CONFIG_TEMPLATE" bash "$PROJECT_DIR/scripts/first_run.sh"
