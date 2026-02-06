#!/usr/bin/env bash
set -euo pipefail

echo "== mytunnel status =="
systemctl status --no-pager mytunnel || true
echo

echo "== recent logs (last 100 lines) =="
journalctl -u mytunnel -n 100 --no-pager || true
echo

echo "== active TCP connections (mytunnel) =="
ss -tnp | grep mytunnel || true
