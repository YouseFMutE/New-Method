use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use dialoguer::{Input, Password, Select};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use socket2::{SockRef, TcpKeepalive};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{mpsc, Mutex},
};
use tokio::sync::mpsc::error::TrySendError;

type HmacSha256 = Hmac<Sha256>;

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const FRAME_OPEN: u8 = 0x01;
const FRAME_DATA: u8 = 0x02;
const FRAME_CLOSE: u8 = 0x03;
const FRAME_KEEPALIVE: u8 = 0x04;
const FRAME_FIN: u8 = 0x05;

const NONCE_LEN: usize = 24;
const MAC_LEN: usize = 32;

#[derive(Debug)]
struct Frame {
    kind: u8,
    id: u32,
    data: Vec<u8>,
}

struct ConnState {
    writer: Mutex<OwnedWriteHalf>,
    local_fin: AtomicBool,
    peer_fin: AtomicBool,
}

type ConnMap = Arc<Mutex<HashMap<u32, Arc<ConnState>>>>;

struct TunnelSession {
    id: u64,
    tx: mpsc::Sender<Frame>,
    conns: ConnMap,
    next_id: AtomicU32,
}

type SessionList = Arc<Mutex<Vec<Arc<TunnelSession>>>>;

#[derive(Parser)]
#[command(name = "mytunnel", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(long, default_value = "config.toml")]
        config: PathBuf,
    },
    Run {
        #[arg(long, default_value = "config.toml")]
        config: PathBuf,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
enum Role {
    Server,
    Client,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
    role: Role,
    psk_hex: String,
    max_frame_size: usize,
    reconnect_delay_ms: u64,
    reconnect_max_delay_ms: u64,
    server: Option<ServerConfig>,
    client: Option<ClientConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ServerConfig {
    tunnel_listen: String,
    public_listen: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ClientConfig {
    server_tunnel: String,
    target: String,
    mux_con: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    log_info(&format!(
        "mytunnel v{} build {}",
        env!("CARGO_PKG_VERSION"),
        option_env!("MYTUNNEL_BUILD").unwrap_or("unknown")
    ));
    match cli.command {
        Commands::Init { config } => run_init(config),
        Commands::Run { config } => run(config).await,
    }
}

fn run_init(config_path: PathBuf) -> Result<()> {
    let role = Select::new()
        .with_prompt("Select role")
        .items(&["server", "client"])
        .default(0)
        .interact()?;
    let role = if role == 0 { Role::Server } else { Role::Client };

    let psk_hex = loop {
        let choice = Select::new()
            .with_prompt("PSK method")
            .items(&["Generate random PSK", "Enter PSK manually"])
            .default(0)
            .interact()?;
        if choice == 0 {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let generated = hex::encode(bytes);
            println!("Generated PSK (64 hex chars): {}", generated);
            let ok: bool = dialoguer::Confirm::new()
                .with_prompt("Use this PSK?")
                .default(true)
                .interact()?;
            if ok {
                break generated;
            }
            continue;
        }

        let psk = Password::new()
            .with_prompt("Enter PSK (hex, 64 chars)")
            .with_confirmation("Confirm PSK", "Mismatch")
            .interact()?;
        if is_valid_psk(&psk) {
            break psk;
        }
        eprintln!("PSK must be 64 hex characters.");
    };

    let max_frame_size: usize = Input::new()
        .with_prompt("Max frame size (bytes)")
        .default(1_048_576)
        .interact_text()?;
    let reconnect_delay_ms: u64 = Input::new()
        .with_prompt("Reconnect delay (ms)")
        .default(1000)
        .interact_text()?;
    let reconnect_max_delay_ms: u64 = Input::new()
        .with_prompt("Reconnect max delay (ms)")
        .default(15000)
        .interact_text()?;

    let (server, client) = match role {
        Role::Server => {
            let tunnel_listen: String = Input::new()
                .with_prompt("Tunnel listen address")
                .default("0.0.0.0:9000".into())
                .interact_text()?;
            let public_listen: String = Input::new()
                .with_prompt("Public listen address")
                .default("0.0.0.0:1414".into())
                .interact_text()?;
            (
                Some(ServerConfig {
                    tunnel_listen,
                    public_listen,
                }),
                None,
            )
        }
        Role::Client => {
            let server_tunnel: String = Input::new()
                .with_prompt("Server tunnel address")
                .default("server.example.com:9000".into())
                .interact_text()?;
            let target: String = Input::new()
                .with_prompt("Target address")
                .default("127.0.0.1:1414".into())
                .interact_text()?;
            let mux_con: u32 = Input::new()
                .with_prompt("TCP mux connections (parallel tunnels)")
                .default(1)
                .interact_text()?;
            (
                None,
                Some(ClientConfig {
                    server_tunnel,
                    target,
                    mux_con: Some(mux_con.max(1)),
                }),
            )
        }
    };

    let config = Config {
        role,
        psk_hex,
        max_frame_size,
        reconnect_delay_ms,
        reconnect_max_delay_ms,
        server,
        client,
    };

    let toml = toml::to_string_pretty(&config)?;
    std::fs::write(&config_path, toml)?;
    println!("Config written to {}", config_path.display());
    Ok(())
}

async fn run(config_path: PathBuf) -> Result<()> {
    let config = load_config(&config_path)?;
    let psk = parse_psk(&config.psk_hex)?;

    match config.role {
        Role::Server => {
            let server = config
                .server
                .clone()
                .ok_or_else(|| anyhow!("Missing server config"))?;
            run_server(server, psk, config.max_frame_size).await
        }
        Role::Client => {
            let client = config
                .client
                .clone()
                .ok_or_else(|| anyhow!("Missing client config"))?;
            run_client(
                client,
                psk,
                config.max_frame_size,
                config.reconnect_delay_ms,
                config.reconnect_max_delay_ms,
            )
            .await
        }
    }
}

fn load_config(path: &PathBuf) -> Result<Config> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config {}", path.display()))?;
    let config: Config = toml::from_str(&content)?;
    if !is_valid_psk(&config.psk_hex) {
        bail!("PSK must be 64 hex characters.");
    }
    Ok(config)
}

async fn run_server(server: ServerConfig, psk: [u8; 32], _max_frame_size: usize) -> Result<()> {
    let tunnel_listen = server.tunnel_listen.clone();
    let public_listen = server.public_listen.clone();

    let tunnel_listener = TcpListener::bind(&tunnel_listen)
        .await
        .with_context(|| format!("Bind tunnel listener {}", tunnel_listen))?;
    let public_listener = TcpListener::bind(&public_listen)
        .await
        .with_context(|| format!("Bind public listener {}", public_listen))?;

    let sessions: SessionList = Arc::new(Mutex::new(Vec::new()));
    let session_seq = Arc::new(AtomicU64::new(1));
    let rr = Arc::new(AtomicUsize::new(0));

    // Accept tunnel connection in background.
    {
        let sessions = Arc::clone(&sessions);
        let session_seq = Arc::clone(&session_seq);
        tokio::spawn(async move {
            loop {
                log_info(&format!(
                    "Waiting for client tunnel on {}",
                    tunnel_listen
                ));
                let (mut tunnel_stream, _) = match tunnel_listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Tunnel accept failed: {e}");
                        continue;
                    }
                };
                apply_socket_opts(&tunnel_stream);
                let peer = tunnel_stream
                    .peer_addr()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|_| "unknown".into());
                if let Err(e) = server_handshake(&mut tunnel_stream, &psk).await {
                    eprintln!("Handshake failed: {e}");
                    continue;
                }
                log_info(&format!("Tunnel connected from {}", peer));

                let (read_half, write_half) = tunnel_stream.into_split();
                let (tx, rx) = mpsc::channel::<Frame>(2048);
                let session = Arc::new(TunnelSession {
                    id: session_seq.fetch_add(1, Ordering::Relaxed),
                    tx: tx.clone(),
                    conns: Arc::new(Mutex::new(HashMap::new())),
                    next_id: AtomicU32::new(1),
                });
                sessions.lock().await.push(Arc::clone(&session));

                let mut writer_task = tokio::spawn(tunnel_writer(write_half, rx));
                let mut reader_task = tokio::spawn(tunnel_reader_server(
                    read_half,
                    Arc::clone(&session.conns),
                    tx,
                ));
                let keepalive_task = tokio::spawn(keepalive_loop(session.tx.clone()));

                tokio::select! {
                    res = &mut reader_task => {
                        match res {
                            Ok(Ok(())) => log_debug("Tunnel reader finished"),
                            Ok(Err(e)) => eprintln!("Tunnel reader error: {e}"),
                            Err(e) => eprintln!("Tunnel reader join error: {e}"),
                        }
                    }
                    res = &mut writer_task => {
                        match res {
                            Ok(Ok(())) => log_debug("Tunnel writer finished"),
                            Ok(Err(e)) => eprintln!("Tunnel writer error: {e}"),
                            Err(e) => eprintln!("Tunnel writer join error: {e}"),
                        }
                    }
                }

                keepalive_task.abort();
                reader_task.abort();
                writer_task.abort();

                {
                    let mut list = sessions.lock().await;
                    list.retain(|s| s.id != session.id);
                }
                close_all_conns(&session.conns).await;
                log_info("Tunnel disconnected");
            }
        });
    }

    log_info(&format!("Public listen on {}", public_listen));
    loop {
        let (socket, _) = public_listener.accept().await?;
        apply_socket_opts(&socket);
        let peer = socket
            .peer_addr()
            .map(|p| p.to_string())
            .unwrap_or_else(|_| "unknown".into());
        log_debug(&format!("Public connection from {}", peer));

        let session = {
            let list = sessions.lock().await;
            if list.is_empty() {
                None
            } else {
                let idx = rr.fetch_add(1, Ordering::Relaxed) % list.len();
                Some(list[idx].clone())
            }
        };
        let session = match session {
            Some(s) => s,
            None => {
                eprintln!("No tunnel connected; dropping incoming connection from {peer}.");
                continue;
            }
        };

        let id = session.next_id.fetch_add(1, Ordering::Relaxed);
        log_debug(&format!("OPEN id={} from {}", id, peer));
        let (read_half, write_half) = socket.into_split();
        let state = Arc::new(ConnState {
            writer: Mutex::new(write_half),
            local_fin: AtomicBool::new(false),
            peer_fin: AtomicBool::new(false),
        });
        session.conns.lock().await.insert(id, Arc::clone(&state));

        if session
            .tx
            .send(Frame {
                kind: FRAME_OPEN,
                id,
                data: Vec::new(),
            })
            .await
            .is_err()
        {
            eprintln!("Failed to send OPEN for id={id}");
            session.conns.lock().await.remove(&id);
            continue;
        }

        let conns = Arc::clone(&session.conns);
        let tx_clone = session.tx.clone();
        tokio::spawn(async move {
            pump_socket_to_tunnel(read_half, id, tx_clone, conns).await;
            log_debug(&format!("FIN id={} from {}", id, peer));
        });
    }
}

async fn run_client(
    client: ClientConfig,
    psk: [u8; 32],
    _max_frame_size: usize,
    reconnect_delay_ms: u64,
    reconnect_max_delay_ms: u64,
) -> Result<()> {
    let mux_con = client.mux_con.unwrap_or(1).max(1);
    for idx in 0..mux_con {
        let client = client.clone();
        tokio::spawn(run_client_session(
            idx as usize,
            client,
            psk,
            reconnect_delay_ms,
            reconnect_max_delay_ms,
        ));
    }
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn run_client_session(
    session_id: usize,
    client: ClientConfig,
    psk: [u8; 32],
    reconnect_delay_ms: u64,
    reconnect_max_delay_ms: u64,
) {
    let mut delay = reconnect_delay_ms;
    let connections: ConnMap = Arc::new(Mutex::new(HashMap::new()));
    loop {
        log_info(&format!(
            "Connecting to server tunnel {} (session {})",
            client.server_tunnel, session_id
        ));
        match TcpStream::connect(&client.server_tunnel).await {
            Ok(mut tunnel_stream) => {
                apply_socket_opts(&tunnel_stream);
                delay = reconnect_delay_ms;
                if let Err(e) = client_handshake(&mut tunnel_stream, &psk).await {
                    eprintln!("Handshake failed: {e}");
                    continue;
                }
                log_info(&format!("Tunnel connected to server (session {})", session_id));
                let (read_half, write_half) = tunnel_stream.into_split();
                let (tx, rx) = mpsc::channel::<Frame>(2048);
                let mut writer_task = tokio::spawn(tunnel_writer(write_half, rx));
                let mut reader_task = tokio::spawn(tunnel_reader_client(
                    read_half,
                    Arc::clone(&connections),
                    tx.clone(),
                    client.target.clone(),
                ));
                let keepalive_task = tokio::spawn(keepalive_loop(tx.clone()));

                tokio::select! {
                    res = &mut reader_task => {
                        match res {
                            Ok(Ok(())) => log_debug(&format!("Tunnel reader finished (session {})", session_id)),
                            Ok(Err(e)) => eprintln!("Tunnel reader error (session {}): {e}", session_id),
                            Err(e) => eprintln!("Tunnel reader join error (session {}): {e}", session_id),
                        }
                    }
                    res = &mut writer_task => {
                        match res {
                            Ok(Ok(())) => log_debug(&format!("Tunnel writer finished (session {})", session_id)),
                            Ok(Err(e)) => eprintln!("Tunnel writer error (session {}): {e}", session_id),
                            Err(e) => eprintln!("Tunnel writer join error (session {}): {e}", session_id),
                        }
                    }
                }

                keepalive_task.abort();
                reader_task.abort();
                writer_task.abort();
                close_all_conns(&connections).await;
            }
            Err(e) => {
                eprintln!("Connect failed: {e}");
            }
        }

        log_info(&format!("Reconnecting in {} ms", delay));
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        delay = std::cmp::min(delay * 2, reconnect_max_delay_ms);
    }
}

async fn tunnel_writer(mut writer: OwnedWriteHalf, mut rx: mpsc::Receiver<Frame>) -> Result<()> {
    while let Some(frame) = rx.recv().await {
        write_frame(&mut writer, &frame).await?;
    }
    Ok(())
}

async fn keepalive_loop(tx: mpsc::Sender<Frame>) {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let frame = Frame {
            kind: FRAME_KEEPALIVE,
            id: 0,
            data: Vec::new(),
        };
        match tx.try_send(frame) {
            Ok(()) => {}
            Err(TrySendError::Closed(_)) => break,
            Err(TrySendError::Full(_)) => {}
        }
    }
}

async fn tunnel_reader_server(
    mut reader: OwnedReadHalf,
    conns: ConnMap,
    tx: mpsc::Sender<Frame>,
) -> Result<()> {
    loop {
        let frame = read_frame(&mut reader).await?;
        match frame.kind {
            FRAME_DATA => {
                let conn = { conns.lock().await.get(&frame.id).cloned() };
                if let Some(conn) = conn {
                    let mut w = conn.writer.lock().await;
                    if let Err(e) = w.write_all(&frame.data).await {
                        eprintln!("Write to public failed: {e}");
                        close_conn(&conns, frame.id).await;
                        let _ = tx
                            .send(Frame {
                                kind: FRAME_CLOSE,
                                id: frame.id,
                                data: Vec::new(),
                            })
                            .await;
                    }
                }
            }
            FRAME_FIN => {
                let conn = { conns.lock().await.get(&frame.id).cloned() };
                if let Some(conn) = conn {
                    log_debug(&format!("RX FIN id={}", frame.id));
                    conn.peer_fin.store(true, Ordering::SeqCst);
                    let mut w = conn.writer.lock().await;
                    let _ = w.shutdown().await;
                    if conn.local_fin.load(Ordering::SeqCst) {
                        conns.lock().await.remove(&frame.id);
                    }
                }
            }
            FRAME_CLOSE => {
                close_conn(&conns, frame.id).await;
            }
            FRAME_KEEPALIVE => {}
            FRAME_OPEN => {}
            _ => {}
        }
    }
}

async fn tunnel_reader_client(
    mut reader: OwnedReadHalf,
    conns: ConnMap,
    tx: mpsc::Sender<Frame>,
    target: String,
) -> Result<()> {
    loop {
        let frame = read_frame(&mut reader).await?;
        match frame.kind {
            FRAME_OPEN => {
                let id = frame.id;
                log_debug(&format!("RX OPEN id={} -> target {}", id, target));
                match TcpStream::connect(&target).await {
                    Ok(socket) => {
                        apply_socket_opts(&socket);
                        let (read_half, write_half) = socket.into_split();
                        let state = Arc::new(ConnState {
                            writer: Mutex::new(write_half),
                            local_fin: AtomicBool::new(false),
                            peer_fin: AtomicBool::new(false),
                        });
                        conns.lock().await.insert(id, Arc::clone(&state));
                        let conns_clone = Arc::clone(&conns);
                        let tx_clone = tx.clone();
                        tokio::spawn(async move {
                            pump_socket_to_tunnel(read_half, id, tx_clone, conns_clone).await;
                        });
                    }
                    Err(e) => {
                        eprintln!("Target connect failed: {e}");
                        let _ = tx
                            .send(Frame {
                                kind: FRAME_CLOSE,
                                id,
                                data: Vec::new(),
                            })
                            .await;
                    }
                }
            }
            FRAME_DATA => {
                let conn = { conns.lock().await.get(&frame.id).cloned() };
                if let Some(conn) = conn {
                    let mut w = conn.writer.lock().await;
                    if let Err(e) = w.write_all(&frame.data).await {
                        eprintln!("Write to target failed: {e}");
                        close_conn(&conns, frame.id).await;
                        let _ = tx
                            .send(Frame {
                                kind: FRAME_CLOSE,
                                id: frame.id,
                                data: Vec::new(),
                            })
                            .await;
                    }
                } else {
                    eprintln!("DATA for unknown id={}", frame.id);
                }
            }
            FRAME_FIN => {
                let conn = { conns.lock().await.get(&frame.id).cloned() };
                if let Some(conn) = conn {
                    log_debug(&format!("RX FIN id={}", frame.id));
                    conn.peer_fin.store(true, Ordering::SeqCst);
                    let mut w = conn.writer.lock().await;
                    let _ = w.shutdown().await;
                    if conn.local_fin.load(Ordering::SeqCst) {
                        conns.lock().await.remove(&frame.id);
                    }
                }
            }
            FRAME_CLOSE => {
                log_debug(&format!("RX CLOSE id={}", frame.id));
                close_conn(&conns, frame.id).await;
            }
            FRAME_KEEPALIVE => {}
            _ => {}
        }
    }
}

async fn pump_socket_to_tunnel(
    mut reader: OwnedReadHalf,
    id: u32,
    tx: mpsc::Sender<Frame>,
    conns: ConnMap,
) {
    let mut buf = vec![0u8; 16 * 1024];
    let mut first = true;
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                log_debug(&format!("TX FIN id={}", id));
                let _ = tx
                    .send(Frame {
                        kind: FRAME_FIN,
                        id,
                        data: Vec::new(),
                    })
                    .await;
                let conn = { conns.lock().await.get(&id).cloned() };
                if let Some(conn) = conn {
                    conn.local_fin.store(true, Ordering::SeqCst);
                    if conn.peer_fin.load(Ordering::SeqCst) {
                        conns.lock().await.remove(&id);
                    }
                }
                return;
            }
            Ok(n) => {
                if first {
                    log_debug(&format!("TX DATA id={} bytes={}", id, n));
                    first = false;
                }
                if tx
                    .send(Frame {
                        kind: FRAME_DATA,
                        id,
                        data: buf[..n].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    let _ = tx
                        .send(Frame {
                            kind: FRAME_CLOSE,
                            id,
                            data: Vec::new(),
                        })
                        .await;
                    close_conn(&conns, id).await;
                    return;
                }
            }
            Err(_) => {
                let _ = tx
                    .send(Frame {
                        kind: FRAME_CLOSE,
                        id,
                        data: Vec::new(),
                    })
                    .await;
                close_conn(&conns, id).await;
                return;
            }
        }
    }
}

async fn close_conn(conns: &ConnMap, id: u32) {
    let conn = { conns.lock().await.remove(&id) };
    if let Some(conn) = conn {
        let mut w = conn.writer.lock().await;
        let _ = w.shutdown().await;
    }
}

async fn close_all_conns(conns: &ConnMap) {
    let list = { conns.lock().await.values().cloned().collect::<Vec<_>>() };
    for conn in list {
        let mut w = conn.writer.lock().await;
        let _ = w.shutdown().await;
    }
    conns.lock().await.clear();
}

async fn write_frame(writer: &mut OwnedWriteHalf, frame: &Frame) -> Result<()> {
    writer.write_all(&[frame.kind]).await?;
    writer.write_all(&frame.id.to_be_bytes()).await?;
    let len = frame.data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    if len > 0 {
        writer.write_all(&frame.data).await?;
    }
    Ok(())
}

async fn read_frame(reader: &mut OwnedReadHalf) -> Result<Frame> {
    let mut header = [0u8; 9];
    reader.read_exact(&mut header).await?;
    let kind = header[0];
    let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let mut data = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut data).await?;
    }
    Ok(Frame { kind, id, data })
}

async fn server_handshake(stream: &mut TcpStream, psk: &[u8; 32]) -> Result<()> {
    let mut msg_type = [0u8; 1];
    log_debug("Handshake: waiting for client hello");
    stream.read_exact(&mut msg_type).await?;
    if msg_type[0] != HANDSHAKE_CLIENT_HELLO {
        bail!("Unexpected handshake");
    }
    let mut client_nonce = [0u8; NONCE_LEN];
    stream.read_exact(&mut client_nonce).await?;
    let mut client_mac = [0u8; MAC_LEN];
    stream.read_exact(&mut client_mac).await?;
    log_debug("Handshake: got client hello");

    let mut data = Vec::with_capacity(6 + NONCE_LEN);
    data.extend_from_slice(b"client");
    data.extend_from_slice(&client_nonce);
    let expected = hmac_tag(psk, &data);
    if !ct_eq(&expected, &client_mac) {
        bail!("Handshake auth failed");
    }
    Ok(())
}

async fn client_handshake(stream: &mut TcpStream, psk: &[u8; 32]) -> Result<()> {
    let mut client_nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut client_nonce);

    let mut data = Vec::with_capacity(6 + NONCE_LEN);
    data.extend_from_slice(b"client");
    data.extend_from_slice(&client_nonce);
    let client_mac = hmac_tag(psk, &data);

    stream.write_all(&[HANDSHAKE_CLIENT_HELLO]).await?;
    stream.write_all(&client_nonce).await?;
    stream.write_all(&client_mac).await?;
    log_debug("Handshake: sent client hello");
    Ok(())
}

fn hmac_tag(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

fn parse_psk(psk_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(psk_hex)?;
    if bytes.len() != 32 {
        bail!("PSK must be 32 bytes (64 hex chars)");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn is_valid_psk(psk_hex: &str) -> bool {
    parse_psk(psk_hex).is_ok()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}


fn log_info(msg: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("[{ts}] {msg}");
}

fn log_debug(msg: &str) {
    if std::env::var("MYTUNNEL_DEBUG").is_ok() {
        log_info(msg);
    }
}

fn apply_socket_opts(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = SockRef::from(stream);
    let _ = sock.set_keepalive(true);
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10))
        .with_retries(5);
    let _ = sock.set_tcp_keepalive(&keepalive);
}
