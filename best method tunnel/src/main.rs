use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use dialoguer::{Input, Password, Select};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
};

const VERSION: u8 = 1;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const HANDSHAKE_CLIENT_ACK: u8 = 0x03;
const HANDSHAKE_SERVER_OK: u8 = 0x04;

const FRAME_OPEN: u8 = 0x01;
const FRAME_DATA: u8 = 0x02;
const FRAME_CLOSE: u8 = 0x03;

const HANDSHAKE_NONCE_LEN: usize = 24;
const AEAD_NONCE_PREFIX_LEN: usize = 4;
const AEAD_NONCE_LEN: usize = 12;
const MAC_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 18; // version(1) + type(1) + stream_id(4) + seq(8) + len(4)

type HmacSha256 = Hmac<Sha256>;

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

#[derive(Debug)]
struct Frame {
    ftype: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

#[derive(Debug)]
enum OutgoingFrame {
    Open { stream_id: u32 },
    Data { stream_id: u32, payload: Vec<u8> },
    Close { stream_id: u32 },
}

#[derive(Clone, Copy)]
struct DirectionCrypto {
    key: [u8; 32],
    nonce_prefix: [u8; AEAD_NONCE_PREFIX_LEN],
}

#[derive(Clone, Copy)]
struct SessionKeys {
    c2s: DirectionCrypto,
    s2c: DirectionCrypto,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
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

async fn run_server(server: ServerConfig, psk: [u8; 32], max_frame_size: usize) -> Result<()> {
    let tunnel_listener = TcpListener::bind(&server.tunnel_listen)
        .await
        .with_context(|| format!("Bind tunnel listener {}", server.tunnel_listen))?;
    let public_listener = TcpListener::bind(&server.public_listen)
        .await
        .with_context(|| format!("Bind public listener {}", server.public_listen))?;

    let stream_map: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let stream_id_ctr = Arc::new(AtomicU32::new(1));
    let tunnel_sender: Arc<Mutex<Option<mpsc::Sender<OutgoingFrame>>>> =
        Arc::new(Mutex::new(None));

    let _tunnel_sender_task = {
        let stream_map = Arc::clone(&stream_map);
        let tunnel_sender = Arc::clone(&tunnel_sender);
        tokio::spawn(async move {
            loop {
                log_info(&format!(
                    "Waiting for client tunnel on {}",
                    server.tunnel_listen
                ));
                let (mut tunnel_stream, _) = match tunnel_listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Tunnel accept failed: {e}");
                        continue;
                    }
                };
                let session = match server_handshake(&mut tunnel_stream, &psk).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Handshake failed: {e}");
                        continue;
                    }
                };
                let (tunnel_reader, tunnel_writer) = tunnel_stream.into_split();
                let writer_tx = spawn_tunnel_writer(tunnel_writer, session.s2c);
                *tunnel_sender.lock().await = Some(writer_tx.clone());

                let reader_res =
                    tunnel_reader_loop(tunnel_reader, session.c2s, max_frame_size, stream_map.clone())
                        .await;
                if let Err(e) = reader_res {
                    eprintln!("Tunnel reader error: {e}");
                }
                *tunnel_sender.lock().await = None;
                stream_map.lock().await.clear();
            }
        })
    };

    log_info(&format!("Public listen on {}", server.public_listen));
    loop {
        let (socket, _) = public_listener.accept().await?;
        let writer_tx = match tunnel_sender.lock().await.clone() {
            Some(tx) => tx,
            None => {
                eprintln!("No tunnel connected; dropping incoming connection.");
                continue;
            }
        };
        let stream_id = stream_id_ctr.fetch_add(1, Ordering::Relaxed);
        let (tx_to_sock, rx_to_sock) = mpsc::channel::<Vec<u8>>(64);
        stream_map.lock().await.insert(stream_id, tx_to_sock);

        writer_tx
            .send(OutgoingFrame::Open { stream_id })
            .await
            .ok();

        let writer_tx_clone = writer_tx.clone();
        let stream_map_clone = Arc::clone(&stream_map);
        tokio::spawn(async move {
            if let Err(e) = handle_local_socket(
                socket,
                stream_id,
                writer_tx_clone,
                rx_to_sock,
                stream_map_clone,
                max_frame_size,
            )
            .await
            {
                eprintln!("Socket handler error: {e}");
            }
        });
    }
    Ok(())
}

async fn run_client(
    client: ClientConfig,
    psk: [u8; 32],
    max_frame_size: usize,
    reconnect_delay_ms: u64,
    reconnect_max_delay_ms: u64,
) -> Result<()> {
    let mut delay = reconnect_delay_ms;
    loop {
        log_info(&format!("Connecting to server tunnel {}", client.server_tunnel));
        match TcpStream::connect(&client.server_tunnel).await {
            Ok(mut tunnel_stream) => {
                delay = reconnect_delay_ms;
                match client_handshake(&mut tunnel_stream, &psk).await {
                    Ok(session) => {
                        let (tunnel_reader, tunnel_writer) = tunnel_stream.into_split();
                        let writer_tx = spawn_tunnel_writer(tunnel_writer, session.c2s);
                        let stream_map: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
                            Arc::new(Mutex::new(HashMap::new()));
                        let target = client.target.clone();
                        let stream_map_clone = Arc::clone(&stream_map);
                        let reader_res = tunnel_reader_loop_client(
                            tunnel_reader,
                            session.s2c,
                            max_frame_size,
                            stream_map_clone,
                            writer_tx.clone(),
                            target,
                        )
                        .await;
                        if let Err(e) = reader_res {
                            eprintln!("Tunnel reader error: {e}");
                        }
                        stream_map.lock().await.clear();
                    }
                    Err(e) => {
                        eprintln!("Handshake failed: {e}");
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

async fn handle_local_socket(
    socket: TcpStream,
    stream_id: u32,
    writer_tx: mpsc::Sender<OutgoingFrame>,
    mut rx_to_sock: mpsc::Receiver<Vec<u8>>,
    stream_map: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    max_frame_size: usize,
) -> Result<()> {
    let (mut reader, mut writer) = socket.into_split();
    let writer_task = tokio::spawn(async move {
        while let Some(data) = rx_to_sock.recv().await {
            if writer.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    let mut buf = vec![0u8; max_frame_size];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        writer_tx
            .send(OutgoingFrame::Data {
                stream_id,
                payload: buf[..n].to_vec(),
            })
            .await
            .ok();
    }

    stream_map.lock().await.remove(&stream_id);
    writer_tx
        .send(OutgoingFrame::Close { stream_id })
        .await
        .ok();
    let _ = writer_task.await;
    Ok(())
}

async fn tunnel_reader_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    crypto: DirectionCrypto,
    max_frame_size: usize,
    stream_map: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
) -> Result<()> {
    let mut expected_seq: u64 = 0;
    loop {
        let frame = read_frame(&mut reader, &crypto, max_frame_size, &mut expected_seq).await?;
        match frame.ftype {
            FRAME_DATA => {
                if let Some(tx) = stream_map.lock().await.get(&frame.stream_id).cloned() {
                    let _ = tx.send(frame.payload).await;
                }
            }
            FRAME_CLOSE => {
                stream_map.lock().await.remove(&frame.stream_id);
            }
            FRAME_OPEN => {
                // Server should not receive OPEN from client in this design
            }
            _ => {}
        }
    }
}

async fn tunnel_reader_loop_client(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    crypto: DirectionCrypto,
    max_frame_size: usize,
    stream_map: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    writer_tx: mpsc::Sender<OutgoingFrame>,
    target: String,
) -> Result<()> {
    let mut expected_seq: u64 = 0;
    loop {
        let frame = read_frame(&mut reader, &crypto, max_frame_size, &mut expected_seq).await?;
        match frame.ftype {
            FRAME_OPEN => {
                let stream_id = frame.stream_id;
                let socket = TcpStream::connect(&target).await?;
                let (tx_to_sock, rx_to_sock) = mpsc::channel::<Vec<u8>>(64);
                stream_map.lock().await.insert(stream_id, tx_to_sock);

                let writer_tx_clone = writer_tx.clone();
                let stream_map_clone = Arc::clone(&stream_map);
                let target_clone = target.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_local_socket(
                        socket,
                        stream_id,
                        writer_tx_clone,
                        rx_to_sock,
                        stream_map_clone,
                        max_frame_size,
                    )
                    .await
                    {
                        eprintln!("Target socket error ({target_clone}): {e}");
                    }
                });
            }
            FRAME_DATA => {
                if let Some(tx) = stream_map.lock().await.get(&frame.stream_id).cloned() {
                    let _ = tx.send(frame.payload).await;
                }
            }
            FRAME_CLOSE => {
                stream_map.lock().await.remove(&frame.stream_id);
            }
            _ => {}
        }
    }
}

fn spawn_tunnel_writer(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    crypto: DirectionCrypto,
) -> mpsc::Sender<OutgoingFrame> {
    let (tx, mut rx) = mpsc::channel::<OutgoingFrame>(1024);
    tokio::spawn(async move {
        let mut seq: u64 = 0;
        while let Some(frame) = rx.recv().await {
            let (ftype, stream_id, payload) = match frame {
                OutgoingFrame::Open { stream_id } => (FRAME_OPEN, stream_id, Vec::new()),
                OutgoingFrame::Data { stream_id, payload } => (FRAME_DATA, stream_id, payload),
                OutgoingFrame::Close { stream_id } => (FRAME_CLOSE, stream_id, Vec::new()),
            };
            if let Err(e) =
                write_frame(&mut writer, ftype, stream_id, seq, &payload, &crypto).await
            {
                eprintln!("Tunnel writer error: {e}");
                break;
            }
            if seq == u64::MAX {
                eprintln!("Sequence exhausted");
                break;
            }
            seq += 1;
        }
        let _ = writer.shutdown().await;
    });
    tx
}

async fn write_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    ftype: u8,
    stream_id: u32,
    seq: u64,
    payload: &[u8],
    crypto: &DirectionCrypto,
) -> Result<()> {
    let cipher_len = payload.len() + TAG_LEN;
    if cipher_len > u32::MAX as usize {
        bail!("Frame too large");
    }

    let mut header = [0u8; HEADER_LEN];
    header[0] = VERSION;
    header[1] = ftype;
    header[2..6].copy_from_slice(&stream_id.to_be_bytes());
    header[6..14].copy_from_slice(&seq.to_be_bytes());
    header[14..18].copy_from_slice(&(cipher_len as u32).to_be_bytes());

    let cipher = ChaCha20Poly1305::new_from_slice(&crypto.key).map_err(|_| anyhow!("bad key"))?;
    let nonce = build_nonce(&crypto.nonce_prefix, seq);
    let nonce = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: payload,
                aad: &header,
            },
        )
        .map_err(|_| anyhow!("encrypt failed"))?;

    writer.write_all(&header).await?;
    writer.write_all(&ciphertext).await?;
    Ok(())
}

async fn read_frame(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    crypto: &DirectionCrypto,
    max_frame_size: usize,
    expected_seq: &mut u64,
) -> Result<Frame> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;
    if header[0] != VERSION {
        bail!("Unsupported version");
    }
    let ftype = header[1];
    let stream_id = u32::from_be_bytes(header[2..6].try_into().unwrap());
    let seq = u64::from_be_bytes(header[6..14].try_into().unwrap());
    let len = u32::from_be_bytes(header[14..18].try_into().unwrap()) as usize;
    if len < TAG_LEN {
        bail!("Frame too small");
    }
    if len > max_frame_size + TAG_LEN {
        bail!("Frame too large: {}", len);
    }

    let mut ciphertext = vec![0u8; len];
    reader.read_exact(&mut ciphertext).await?;

    let cipher = ChaCha20Poly1305::new_from_slice(&crypto.key).map_err(|_| anyhow!("bad key"))?;
    let nonce = build_nonce(&crypto.nonce_prefix, seq);
    let nonce = Nonce::from_slice(&nonce);
    let payload = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext,
                aad: &header,
            },
        )
        .map_err(|_| anyhow!("decrypt failed"))?;

    if seq != *expected_seq {
        bail!("Bad sequence");
    }
    if *expected_seq == u64::MAX {
        bail!("Sequence exhausted");
    }
    *expected_seq += 1;

    Ok(Frame {
        ftype,
        stream_id,
        payload,
    })
}

async fn server_handshake(stream: &mut TcpStream, psk: &[u8; 32]) -> Result<SessionKeys> {
    let mut msg_type = [0u8; 1];
    stream.read_exact(&mut msg_type).await?;
    if msg_type[0] != HANDSHAKE_CLIENT_HELLO {
        bail!("Unexpected handshake");
    }
    let mut client_nonce = [0u8; HANDSHAKE_NONCE_LEN];
    stream.read_exact(&mut client_nonce).await?;

    let mut server_nonce = [0u8; HANDSHAKE_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut server_nonce);

    let mut data = Vec::with_capacity(6 + HANDSHAKE_NONCE_LEN * 2);
    data.extend_from_slice(b"server");
    data.extend_from_slice(&client_nonce);
    data.extend_from_slice(&server_nonce);
    let server_mac = hmac_tag(psk, &data);

    stream.write_all(&[HANDSHAKE_SERVER_HELLO]).await?;
    stream.write_all(&server_nonce).await?;
    stream.write_all(&server_mac).await?;

    stream.read_exact(&mut msg_type).await?;
    if msg_type[0] != HANDSHAKE_CLIENT_ACK {
        bail!("Unexpected handshake");
    }
    let mut client_mac = [0u8; MAC_LEN];
    stream.read_exact(&mut client_mac).await?;

    let mut data = Vec::with_capacity(6 + HANDSHAKE_NONCE_LEN * 2);
    data.extend_from_slice(b"client");
    data.extend_from_slice(&server_nonce);
    data.extend_from_slice(&client_nonce);
    let expected = hmac_tag(psk, &data);
    if !ct_eq(&expected, &client_mac) {
        bail!("Handshake auth failed");
    }

    stream.write_all(&[HANDSHAKE_SERVER_OK]).await?;

    Ok(derive_session_keys(psk, &client_nonce, &server_nonce)?)
}

async fn client_handshake(stream: &mut TcpStream, psk: &[u8; 32]) -> Result<SessionKeys> {
    let mut client_nonce = [0u8; HANDSHAKE_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut client_nonce);

    stream.write_all(&[HANDSHAKE_CLIENT_HELLO]).await?;
    stream.write_all(&client_nonce).await?;

    let mut msg_type = [0u8; 1];
    stream.read_exact(&mut msg_type).await?;
    if msg_type[0] != HANDSHAKE_SERVER_HELLO {
        bail!("Unexpected handshake");
    }
    let mut server_nonce = [0u8; HANDSHAKE_NONCE_LEN];
    stream.read_exact(&mut server_nonce).await?;
    let mut server_mac = [0u8; MAC_LEN];
    stream.read_exact(&mut server_mac).await?;

    let mut data = Vec::with_capacity(6 + HANDSHAKE_NONCE_LEN * 2);
    data.extend_from_slice(b"server");
    data.extend_from_slice(&client_nonce);
    data.extend_from_slice(&server_nonce);
    let expected = hmac_tag(psk, &data);
    if !ct_eq(&expected, &server_mac) {
        bail!("Handshake auth failed");
    }

    let mut data = Vec::with_capacity(6 + HANDSHAKE_NONCE_LEN * 2);
    data.extend_from_slice(b"client");
    data.extend_from_slice(&server_nonce);
    data.extend_from_slice(&client_nonce);
    let client_mac = hmac_tag(psk, &data);

    stream.write_all(&[HANDSHAKE_CLIENT_ACK]).await?;
    stream.write_all(&client_mac).await?;

    stream.read_exact(&mut msg_type).await?;
    if msg_type[0] != HANDSHAKE_SERVER_OK {
        bail!("Handshake failed");
    }

    Ok(derive_session_keys(psk, &client_nonce, &server_nonce)?)
}

fn derive_session_keys(
    psk: &[u8; 32],
    client_nonce: &[u8; HANDSHAKE_NONCE_LEN],
    server_nonce: &[u8; HANDSHAKE_NONCE_LEN],
) -> Result<SessionKeys> {
    let mut salt = Vec::with_capacity(HANDSHAKE_NONCE_LEN * 2);
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), psk);
    let mut okm = [0u8; 72];
    hkdf.expand(b"tunnel-v1-keys", &mut okm)
        .map_err(|_| anyhow!("HKDF expand failed"))?;

    let mut c2s_key = [0u8; 32];
    c2s_key.copy_from_slice(&okm[0..32]);
    let mut s2c_key = [0u8; 32];
    s2c_key.copy_from_slice(&okm[32..64]);
    let mut c2s_nonce_prefix = [0u8; AEAD_NONCE_PREFIX_LEN];
    c2s_nonce_prefix.copy_from_slice(&okm[64..68]);
    let mut s2c_nonce_prefix = [0u8; AEAD_NONCE_PREFIX_LEN];
    s2c_nonce_prefix.copy_from_slice(&okm[68..72]);

    Ok(SessionKeys {
        c2s: DirectionCrypto {
            key: c2s_key,
            nonce_prefix: c2s_nonce_prefix,
        },
        s2c: DirectionCrypto {
            key: s2c_key,
            nonce_prefix: s2c_nonce_prefix,
        },
    })
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

fn build_nonce(prefix: &[u8; AEAD_NONCE_PREFIX_LEN], seq: u64) -> [u8; AEAD_NONCE_LEN] {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce[..AEAD_NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[AEAD_NONCE_PREFIX_LEN..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

fn log_info(msg: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("[{ts}] {msg}");
}
