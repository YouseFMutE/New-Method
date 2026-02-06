# Minimal Reverse TCP Tunnel (Go)

## High-level architecture
- Two binaries: `client` and `server`.
- The `client` initiates a single TCP connection to the `server` and performs a minimal token handshake.
- After handshake, both sides enter a bidirectional forwarding loop between the TCP stream and their local stdin/stdout. This keeps the interface minimal (only server IP/port/token) and avoids extra configuration.

Separation of concerns (in each binary):
- Networking: connect/accept + handshake + socket configuration.
- Lifecycle control: shutdown signaling + Ctrl-C handling.
- I/O forwarding: byte copy loops with explicit socket read/write timeouts.
- Deterministic shutdown: explicit socket shutdown and task completion before exit.

## Connection lifecycle
### Startup
1. Client connects to the server with a connect timeout.
2. Client sends a length-prefixed token.
3. Server reads and compares the token.
4. Server replies with a 1-byte success/failure response.
5. On success, both sides begin forwarding.

### Runtime
- Two concurrent forwarding loops run:
  - stdin -> socket (write timeout enforced on the socket).
  - socket -> stdout (read timeout enforced on the socket).
- Socket read timeouts do not kill the session; they allow the loop to stay responsive to shutdown signals.
- If stdin reaches EOF, only the write half is closed; the read half continues until the remote closes.

### Shutdown
- Client or server can explicitly terminate by Ctrl-C.
- When shutdown is requested:
  - The write half of the TCP stream is explicitly shut down (FIN).
  - The connection is closed to release all resources.
  - Both forwarding loops are awaited before the process exits.
- When the remote side closes first:
  - The local read loop sees EOF.
  - Shutdown is triggered and the socket is closed explicitly.

## How stale TCP state is avoided
- No session IDs or cached state exist.
- Each run creates a brand-new TCP connection and performs a fresh handshake.
- On shutdown, the program explicitly closes the TCP connection (and its write half), preventing half-open connections from lingering.

## Restart safety
- Both binaries are stateless across restarts.
- Restarting either side always creates a new TCP connection and handshake.
- No background tasks survive shutdown; all forwarding loops are awaited before exit. To avoid a blocked stdin read on shutdown, stdin is explicitly closed during teardown.

## Running on Ubuntu 24.04 (step-by-step)
1. Install Go (if not already present):
   ```bash
   sudo apt update
   sudo apt install -y golang
   ```
2. From the project directory, run the interactive script:
   ```bash
   ./run.sh
   ```
3. Provide:
   - Mode: `server` or `client`
   - Server IP (bind address for server, destination for client)
   - Server port
   - Shared token

The script builds the chosen binary and runs it with your inputs.

## Known limitations (intentional)
- No encryption or authentication beyond a shared token.
- No multiplexing or multiple concurrent clients.
- No auto-reconnect logic.
- No additional local forwarding ports (stdin/stdout is used to keep inputs minimal).
- No configuration hot-reload.

## Notes on ambiguity
The prompt does not specify extra local ports or target addresses. To keep the design minimal and use only the required inputs, the tunnel forwards between the TCP connection and local stdin/stdout. This avoids hidden defaults and preserves explicit lifecycle control while keeping the interface minimal.
