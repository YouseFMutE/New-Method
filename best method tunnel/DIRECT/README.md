# DIRECT tunnel (SSH port forward)

This is a standard, encrypted SSH port-forward that runs on **Server** and forwards
incoming TCP connections to **Client**.

## Quick start
On **Server**:

```bash
chmod +x /Users/dayanland/Personal/New Method/best method tunnel/DIRECT/direct_tunnel.sh

CLIENT_HOST="x.x.x.x" \
SSH_USER="your_ssh_user" \
SSH_KEY="/path/to/private_key" \
SERVER_LISTEN_PORT=1414 \
TARGET_PORT=1414 \
/Users/dayanland/Personal/New Method/best method tunnel/DIRECT/direct_tunnel.sh
```

Then, any connection to `Server:1414` is forwarded to `Client:1414`.

## Variables
- `CLIENT_HOST` (required): Client public IP/hostname.
- `SSH_USER` (required): SSH username on Client.
- `SSH_HOST`: SSH destination host if different from `CLIENT_HOST`.
- `SSH_PORT`: SSH port on Client (default `22`).
- `SSH_KEY`: Path to SSH private key (recommended).
- `SERVER_LISTEN_ADDR`: Address to bind on Server (default `0.0.0.0`).
- `SERVER_LISTEN_PORT`: Port to expose on Server (default `1414`).
- `TARGET_HOST`: Target host on Client (default `127.0.0.1`).
- `TARGET_PORT`: Target port on Client (default `1414`).

## Notes
- This does **not** obfuscate traffic; it is a standard SSH tunnel.
- For security: use key-only SSH auth, disable password login, and firewall the
  exposed port to trusted IPs.
- If `autossh` is installed, the script will auto-reconnect on drops.
