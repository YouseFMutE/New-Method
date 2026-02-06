#!/usr/bin/env bash
set -euo pipefail

COLOR_CYAN="\033[1;36m"
COLOR_YELLOW="\033[1;33m"
COLOR_DIM="\033[2m"
COLOR_RESET="\033[0m"

prompt() {
  local label="$1"
  local var
  read -r -p "$label" var
  printf "%s" "$var"
}

banner() {
  printf "%b" "$COLOR_CYAN"
  cat <<'BANNER'
==================================================
      JJJJJJ    AAA    III   K   K  U   U  PPPP  PPPP
        JJ     A   A    I    K  K   U   U  P   P P   P
        JJ     AAAAA    I    KKK    U   U  PPPP  PPPP
   J    JJ     A   A    I    K  K   U   U  P     P
    JJJJ       A   A   III   K   K   UUU   P     P
==================================================
BANNER
  printf "%b" "$COLOR_RESET"
}

menu() {
  local choice
  while true; do
    echo
    printf "%b" "$COLOR_YELLOW"
    echo "Minimal Reverse TCP Tunnel"
    printf "%b" "$COLOR_RESET"
    echo "1) Client"
    echo "2) Server"
    echo "3) Exit"
    read -r -p "Select option [1-3]: " choice
    case "$choice" in
      1|client|Client)
        mode="client"
        return
        ;;
      2|server|Server)
        mode="server"
        return
        ;;
      3|exit|quit|q|Q)
        exit 0
        ;;
      *)
        printf "%b" "$COLOR_DIM"
        echo "Invalid selection. Try again."
        printf "%b" "$COLOR_RESET"
        ;;
    esac
  done
}

mode=""

clear || true
banner
menu

echo
server_ip=$(prompt "Server IP (client: destination, server: bind address): ")
server_port=$(prompt "Server port: ")
shared_token=$(prompt "Shared token: ")

echo "Building..."
if [[ "$mode" == "client" ]]; then
  go build -o ./client ./client.go
  echo "Running client..."
  ./client "$server_ip" "$server_port" "$shared_token"
else
  go build -o ./server ./server.go
  echo "Running server..."
  ./server "$server_ip" "$server_port" "$shared_token"
fi
