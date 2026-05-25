mod args;
mod auth;
mod http_logger;
mod http_utils;
mod logger;
mod noscript;
mod server;
mod utils;

#[macro_use]
extern crate log;

use crate::args::{build_cli, print_completions, Args};
use crate::server::Server;
#[cfg(feature = "tls")]
use crate::utils::{load_certs, load_private_key};

use anyhow::{anyhow, bail, Context, Result};
use args::BindAddr;
use clap_complete::Shell;
use futures_util::future::join_all;

use hyper::{body::Incoming, service::service_fn, Request};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::time::timeout;
use tokio::{net::TcpListener, task::JoinHandle};
#[cfg(feature = "tls")]
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};

#[tokio::main]
async fn main() -> Result<()> {
    let cmd = build_cli();
    let matches = cmd.get_matches();
    if let Some(generator) = matches.get_one::<Shell>("completions") {
        let mut cmd = build_cli();
        print_completions(*generator, &mut cmd);
        return Ok(());
    }
    let mut args = Args::parse(matches)?;
    logger::init(args.log_file.clone()).map_err(|e| anyhow!("Failed to init logger, {e}"))?;

    let ip_a = detect_outgoing_ip()?;
    let port_b = find_available_port(args.port)?;
    args.port = port_b;
    args.addrs = vec![BindAddr::IpAddr("0.0.0.0".parse().unwrap())];

    let running = Arc::new(AtomicBool::new(true));

    let protocol = if args.tls_cert.is_some() {
        "https"
    } else {
        "http"
    };
    let url = format!("{}://{}:{}{}", protocol, ip_a, port_b, args.uri_prefix);

    // 打印跟路径前提
    let served_path = args.serve_path.clone();

    let handles = serve(args, running.clone())?;

    println!(
        "  🖥️📱  局域网文件互传(LAN FileTransfer)\n\n  1.浏览器(Web):  {}\n  2.浏览器扫码(WebScanCode):",
        url
    );
    print_qr_code(&url);
    // 打印跟路径
    let path_to_print = if let Ok(abs_path) = std::fs::canonicalize(&served_path) {
        let path_str = abs_path.to_string_lossy().into_owned();
        // 如果是以 \\?\ 开头的 Windows UNC 路径，则截取掉前 4 个字符
        if path_str.starts_with(r"\\?\") {
            //path_str[4..].to_string()  优化代码检查，替换为下面这行
            path_str.strip_prefix(r"\\?\").unwrap().to_string()
        } else {
            path_str
        }
    } else {
        served_path.to_string_lossy().into_owned()
    };

    println!("  🏠 {}", path_to_print);

    tokio::select! {
        ret = join_all(handles) => {
            for r in ret {
                if let Err(e) = r {
                    error!("{e}");
                }
            }
            Ok(())
        },
        _ = shutdown_signal() => {
            running.store(false, Ordering::SeqCst);
            Ok(())
        },
    }
}

fn serve(args: Args, running: Arc<AtomicBool>) -> Result<Vec<JoinHandle<()>>> {
    let addrs = args.addrs.clone();
    let port = args.port;
    let tls_config = (args.tls_cert.clone(), args.tls_key.clone());
    let server_handle = Arc::new(Server::init(args, running)?);
    let mut handles = vec![];
    for bind_addr in addrs.iter() {
        let server_handle = server_handle.clone();
        match bind_addr {
            BindAddr::IpAddr(ip) => {
                let listener = create_listener(SocketAddr::new(*ip, port))
                    .with_context(|| format!("Failed to bind `{ip}:{port}`"))?;

                match &tls_config {
                    #[cfg(feature = "tls")]
                    (Some(cert_file), Some(key_file)) => {
                        let certs = load_certs(cert_file)?;
                        let key = load_private_key(key_file)?;
                        let mut config = ServerConfig::builder()
                            .with_no_client_auth()
                            .with_single_cert(certs, key)?;
                        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                        let config = Arc::new(config);
                        let tls_accepter = TlsAcceptor::from(config);
                        let handshake_timeout = Duration::from_secs(10);

                        let handle = tokio::spawn(async move {
                            loop {
                                let Ok((stream, addr)) = listener.accept().await else {
                                    continue;
                                };
                                let Some(stream) =
                                    timeout(handshake_timeout, tls_accepter.accept(stream))
                                        .await
                                        .ok()
                                        .and_then(|v| v.ok())
                                else {
                                    continue;
                                };
                                let stream = TokioIo::new(stream);
                                tokio::spawn(handle_stream(
                                    server_handle.clone(),
                                    stream,
                                    Some(addr),
                                ));
                            }
                        });

                        handles.push(handle);
                    }
                    (None, None) => {
                        let handle = tokio::spawn(async move {
                            loop {
                                let Ok((stream, addr)) = listener.accept().await else {
                                    continue;
                                };
                                let stream = TokioIo::new(stream);
                                tokio::spawn(handle_stream(
                                    server_handle.clone(),
                                    stream,
                                    Some(addr),
                                ));
                            }
                        });
                        handles.push(handle);
                    }
                    _ => {
                        unreachable!()
                    }
                };
            }
            #[cfg(unix)]
            BindAddr::SocketPath(path) => {
                let socket_path = if path.starts_with("@")
                    && cfg!(any(target_os = "linux", target_os = "android"))
                {
                    let mut path_buf = path.as_bytes().to_vec();
                    path_buf[0] = b'\0';
                    unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(&path_buf) }
                        .to_os_string()
                } else {
                    let _ = std::fs::remove_file(path);
                    path.into()
                };
                let listener = tokio::net::UnixListener::bind(socket_path)
                    .with_context(|| format!("Failed to bind `{path}`"))?;
                let handle = tokio::spawn(async move {
                    loop {
                        let Ok((stream, _addr)) = listener.accept().await else {
                            continue;
                        };
                        let stream = TokioIo::new(stream);
                        tokio::spawn(handle_stream(server_handle.clone(), stream, None));
                    }
                });

                handles.push(handle);
            }
        }
    }
    Ok(handles)
}

async fn handle_stream<T>(handle: Arc<Server>, stream: TokioIo<T>, addr: Option<SocketAddr>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let hyper_service =
        service_fn(move |request: Request<Incoming>| handle.clone().call(request, addr));

    match Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(stream, hyper_service)
        .await
    {
        Ok(()) => {}
        Err(_err) => {
            // This error only appears when the client doesn't send a request and terminate the connection.
            //
            // If client sends one request then terminate connection whenever, it doesn't appear.
        }
    }
}

fn create_listener(addr: SocketAddr) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024 /* Default backlog */)?;
    let std_listener = StdTcpListener::from(socket);
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    Ok(listener)
}

fn detect_outgoing_ip() -> Result<IpAddr> {
    use std::net::UdpSocket;
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if let Ok(()) = socket.connect("8.8.8.8:80") {
            if let Ok(addr) = socket.local_addr() {
                let ip = addr.ip();
                if !ip.is_loopback() && !ip.is_unspecified() {
                    return Ok(ip);
                }
            }
        }
    }
    let ifaces =
        if_addrs::get_if_addrs().with_context(|| "Failed to get local interface addresses")?;
    for iface in ifaces {
        let ip = iface.ip();
        if ip.is_ipv4() && !ip.is_loopback() {
            return Ok(ip);
        }
    }
    bail!("No suitable network interface found")
}

fn find_available_port(preferred: u16) -> Result<u16> {
    if std::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], preferred))).is_ok() {
        return Ok(preferred);
    }
    // eprintln!(
    //     "Port {} is already in use, selecting an available port...",
    //     preferred
    // );
    let listener = std::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
        .with_context(|| "Failed to find an available port")?;
    Ok(listener.local_addr()?.port())
}

fn print_qr_code(url: &str) {
    use qrcode::types::Color;
    use qrcode::QrCode;

    enable_ansi_support();

    let qr_data = url.to_uppercase();
    let code = match QrCode::with_error_correction_level(qr_data.as_bytes(), qrcode::EcLevel::L) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to generate QR code: {}", e);
            return;
        }
    };

    let width = code.width();
    let colors = code.to_colors();

    let quiet = 1usize;
    let total_w = width + quiet * 2;
    let total_h = width + quiet * 2;

    let is_dark = |r: usize, c: usize| -> bool {
        r >= quiet
            && r < quiet + width
            && c >= quiet
            && c < quiet + width
            && colors[(r - quiet) * width + (c - quiet)] == Color::Dark
    };

    for row in (0..total_h).step_by(2) {
        let mut line = String::from("  ");
        line.push_str("\x1b[107m\x1b[30m");

        for col in 0..total_w {
            let top_dark = is_dark(row, col);
            let bottom_dark = if row + 1 < total_h {
                is_dark(row + 1, col)
            } else {
                false
            };

            let ch = match (top_dark, bottom_dark) {
                (false, false) => " ",
                (true, false) => "▀",
                (false, true) => "▄",
                (true, true) => "█",
            };
            line.push_str(ch);
        }
        line.push_str("\x1b[0m");
        println!("{}", line);
    }
}

fn enable_ansi_support() {
    #[cfg(windows)]
    unsafe {
        extern "system" {
            fn GetStdHandle(nStdHandle: u32) -> isize;
            fn GetConsoleMode(hConsoleHandle: isize, lpMode: *mut u32) -> i32;
            fn SetConsoleMode(hConsoleHandle: isize, dwMode: u32) -> i32;
        }
        let handle = GetStdHandle((-11i32) as u32);
        let mut mode: u32 = 0;
        if GetConsoleMode(handle, &mut mode) != 0 {
            let _ = SetConsoleMode(handle, mode | 0x0004);
        }
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler")
}
