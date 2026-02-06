#!/usr/bin/env bash
set -euo pipefail

# Secure TCP port forward from Server -> Client over SSH.
# Run this script on the Server (Iran side).

# Required
CLIENT_HOST="${CLIENT_HOST:?set CLIENT_HOST (public IP or hostname of Client)}"
SSH_USER="${SSH_USER:?set SSH_USER (ssh username on Client)}"

# Optional
SSH_HOST="${SSH_HOST:-$CLIENT_HOST}"
SSH_PORT="${SSH_PORT:-22}"
SSH_KEY="${SSH_KEY:-}"
SERVER_LISTEN_ADDR="${SERVER_LISTEN_ADDR:-0.0.0.0}"
SERVER_LISTEN_PORT="${SERVER_LISTEN_PORT:-1414}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-1414}"

COMMON_OPTS=(
  -p "$SSH_PORT"
  -o ExitOnForwardFailure=yes
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=3
  -o TCPKeepAlive=yes
  -N
  -L "${SERVER_LISTEN_ADDR}:${SERVER_LISTEN_PORT}:${TARGET_HOST}:${TARGET_PORT}"
)

if [[ -n "$SSH_KEY" ]]; then
  COMMON_OPTS+=( -i "$SSH_KEY" )
fi

if command -v autossh >/dev/null 2>&1; then
  exec autossh -M 0 -g "${COMMON_OPTS[@]}" "${SSH_USER}@${SSH_HOST}"
else
  exec ssh -g "${COMMON_OPTS[@]}" "${SSH_USER}@${SSH_HOST}"
fi
