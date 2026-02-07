use std::{
    path::PathBuf,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use dialoguer::{Input, Password, Select};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_yamux::{Config as YamuxConfig, Control, Session};
use tokio_yamux::session::SessionType;

type HmacSha256 = Hmac<Sha256>;

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_CLIENT_ACK: u8 = 0x03;
const HANDSHAKE_SERVER_OK: u8 = 0x04;

const NONCE_LEN: usize = 24;
const MAC_LEN: usize = 32;

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
            (
                None,
                Some(ClientConfig {
                    server_tunnel,
                    target,
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
            run_server(server, psk).await
        }
        Role::Client => {
            let client = config
                .client
                .clone()
                .ok_or_else(|| anyhow!("Missing client config"))?;
            run_client(
                client,
                psk,
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

async fn run_server(server: ServerConfig, psk: [u8; 32]) -> Result<()> {
    let tunnel_listen = server.tunnel_listen.clone();
    let public_listen = server.public_listen.clone();

    let tunnel_listener = TcpListener::bind(&tunnel_listen)
        .await
        .with_context(|| format!("Bind tunnel listener {}", tunnel_listen))?;
    let public_listener = TcpListener::bind(&public_listen)
        .await
        .with_context(|| format!("Bind public listener {}", public_listen))?;

    let control: Arc<Mutex<Option<Arc<Mutex<Control>>>>> = Arc::new(Mutex::new(None));

    // Accept tunnel connection in background.
    {
        let control = Arc::clone(&control);
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
                let peer = tunnel_stream
                    .peer_addr()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|_| "unknown".into());
                if let Err(e) = server_handshake(&mut tunnel_stream, &psk).await {
                    eprintln!("Handshake failed: {e}");
                    continue;
                }
                log_info(&format!("Tunnel connected from {}", peer));

                let mut yamux = Session::new(tunnel_stream, YamuxConfig::default(), SessionType::Server);
                *control.lock().await = Some(Arc::new(Mutex::new(yamux.control())));

                while let Some(res) = yamux.next().await {
                    if let Err(e) = res {
                        eprintln!("Yamux error: {e}");
                        break;
                    }
                    // Server side shouldn't receive inbound streams; ignore.
                }

                *control.lock().await = None;
                log_info("Tunnel disconnected");
            }
        });
    }

    log_info(&format!("Public listen on {}", public_listen));
    loop {
        let (mut socket, _) = public_listener.accept().await?;
        let peer = socket
            .peer_addr()
            .map(|p| p.to_string())
            .unwrap_or_else(|_| "unknown".into());
        log_debug(&format!("Public connection from {}", peer));
        let control_opt = control.lock().await.clone();
        let control = match control_opt {
            Some(c) => c,
            None => {
                eprintln!("No tunnel connected; dropping incoming connection from {peer}.");
                continue;
            }
        };

        tokio::spawn(async move {
            let stream_res = {
                let mut ctrl = control.lock().await;
                ctrl.open_stream().await
            };
            match stream_res {
                Ok(stream) => {
                    log_debug(&format!("Opened tunnel stream for {}", peer));
                    let mut stream = stream;
                    match copy_bidirectional(&mut socket, &mut stream).await {
                        Ok((a, b)) => log_debug(&format!(
                            "Public {} closed (up {} bytes, down {} bytes)",
                            peer, a, b
                        )),
                        Err(e) => eprintln!("Copy failed for {peer}: {e}"),
                    }
                }
                Err(e) => {
                    eprintln!("Open stream failed: {e}");
                }
            }
        });
    }
}

async fn run_client(
    client: ClientConfig,
    psk: [u8; 32],
    reconnect_delay_ms: u64,
    reconnect_max_delay_ms: u64,
) -> Result<()> {
    let mut delay = reconnect_delay_ms;
    loop {
        log_info(&format!("Connecting to server tunnel {}", client.server_tunnel));
        match TcpStream::connect(&client.server_tunnel).await {
            Ok(mut tunnel_stream) => {
                delay = reconnect_delay_ms;
                if let Err(e) = client_handshake(&mut tunnel_stream, &psk).await {
                    eprintln!("Handshake failed: {e}");
                    continue;
                }
                log_info("Tunnel connected to server");

                let mut yamux = Session::new(tunnel_stream, YamuxConfig::default(), SessionType::Client);
                while let Some(res) = yamux.next().await {
                    match res {
                        Ok(stream) => {
                            log_debug("Inbound stream from server");
                            let target = client.target.clone();
                            tokio::spawn(async move {
                                match TcpStream::connect(&target).await {
                                    Ok(mut target_sock) => {
                                        log_debug(&format!("Connected to target {}", target));
                                        let mut stream = stream;
                                        match copy_bidirectional(&mut stream, &mut target_sock).await {
                                            Ok((a, b)) => log_debug(&format!(
                                                "Target {} closed (up {} bytes, down {} bytes)",
                                                target, a, b
                                            )),
                                            Err(e) => eprintln!("Copy failed for target {target}: {e}"),
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("Target connect failed: {e}");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("Yamux error: {e}");
                            break;
                        }
                    }
                }
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

async fn server_handshake(stream: &mut TcpStream, psk: &[u8; 32]) -> Result<()> {
    let mut msg_type = [0u8; 1];
    log_debug("Handshake: waiting for client hello");
    stream.read_exact(&mut msg_type).await?;
    if msg_type[0] != HANDSHAKE_CLIENT_HELLO {
        bail!("Unexpected handshake");
    }
    let mut client_nonce = [0u8; NONCE_LEN];
    stream.read_exact(&mut client_nonce).await?;
    log_debug("Handshake: got client hello");

    let mut server_nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut server_nonce);

    let mut data = Vec::with_capacity(6 + NONCE_LEN * 2);
    data.extend_from_slice(b"server");
    data.extend_from_slice(&client_nonce);
    data.extend_from_slice(&server_nonce);
    let server_mac = hmac_tag(psk, &data);

    stream.write_all(&[HANDSHAKE_SERVER_HELLO]).await?;
    stream.write_all(&server_nonce).await?;
    stream.write_all(&server_mac).await?;
    log_debug("Handshake: sent server hello");

    stream.read_exact(&mut msg_type).await?;
    if msg_type[0] != HANDSHAKE_CLIENT_ACK {
        bail!("Unexpected handshake");
    }
    let mut client_mac = [0u8; MAC_LEN];
    stream.read_exact(&mut client_mac).await?;
    log_debug("Handshake: got client ack");

    let mut data = Vec::with_capacity(6 + NONCE_LEN * 2);
    data.extend_from_slice(b"client");
    data.extend_from_slice(&server_nonce);
    data.extend_from_slice(&client_nonce);
    let expected = hmac_tag(psk, &data);
    if !ct_eq(&expected, &client_mac) {
        bail!("Handshake auth failed");
    }

    stream.write_all(&[HANDSHAKE_SERVER_OK]).await?;
    log_debug("Handshake: sent server ok");
    Ok(())
}

async fn client_handshake(stream: &mut TcpStream, psk: &[u8; 32]) -> Result<()> {
    let mut client_nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut client_nonce);

    stream.write_all(&[HANDSHAKE_CLIENT_HELLO]).await?;
    stream.write_all(&client_nonce).await?;
    log_debug("Handshake: sent client hello");

    let mut msg_type = [0u8; 1];
    stream.read_exact(&mut msg_type).await?;
    if msg_type[0] != HANDSHAKE_SERVER_HELLO {
        bail!("Unexpected handshake");
    }
    let mut server_nonce = [0u8; NONCE_LEN];
    stream.read_exact(&mut server_nonce).await?;
    let mut server_mac = [0u8; MAC_LEN];
    stream.read_exact(&mut server_mac).await?;
    log_debug("Handshake: got server hello");

    let mut data = Vec::with_capacity(6 + NONCE_LEN * 2);
    data.extend_from_slice(b"server");
    data.extend_from_slice(&client_nonce);
    data.extend_from_slice(&server_nonce);
    let expected = hmac_tag(psk, &data);
    if !ct_eq(&expected, &server_mac) {
        bail!("Handshake auth failed");
    }

    let mut data = Vec::with_capacity(6 + NONCE_LEN * 2);
    data.extend_from_slice(b"client");
    data.extend_from_slice(&server_nonce);
    data.extend_from_slice(&client_nonce);
    let client_mac = hmac_tag(psk, &data);

    stream.write_all(&[HANDSHAKE_CLIENT_ACK]).await?;
    stream.write_all(&client_mac).await?;
    log_debug("Handshake: sent client ack");

    stream.read_exact(&mut msg_type).await?;
    if msg_type[0] != HANDSHAKE_SERVER_OK {
        bail!("Handshake failed");
    }
    log_debug("Handshake: got server ok");
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
