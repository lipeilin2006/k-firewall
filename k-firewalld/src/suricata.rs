use std::fs::File;
use std::io::{BufRead as _, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};

use crate::config::Suricata;

/// Suricata 告警触发的一条自动封禁请求。
#[derive(Debug, Clone)]
pub struct Alert {
    pub ip: IpAddr,
    pub severity: u8,
    pub signature: String,
    /// 封禁秒数；`None` = 永久。
    pub block_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct EveRecord {
    event_type: String,
    src_ip: Option<String>,
    alert: Option<EveAlert>,
}

#[derive(Debug, Deserialize)]
struct EveAlert {
    severity: Option<u8>,
    signature: Option<String>,
}

/// 启动 Suricata eve 监听。优先 Unix socket；socket 不可用或断开后
/// 回退到 eve.json 文件 tail 跟踪。
pub fn spawn(cfg: &Suricata, tx: UnboundedSender<Alert>) {
    match (&cfg.eve_socket, &cfg.eve_file) {
        (Some(sock), Some(file)) => {
            let (sock, file) = (sock.clone(), file.clone());
            tokio::spawn(socket_with_file_fallback(sock, file, cfg.clone(), tx));
        }
        (Some(sock), None) => {
            let sock = sock.clone();
            let cfg = cfg.clone();
            tokio::spawn(async move {
                loop {
                    match tokio::net::UnixStream::connect(&sock).await {
                        Ok(stream) => {
                            info!("connected to Suricata eve socket {}", sock.display());
                            read_socket(stream, &cfg, &tx).await;
                        }
                        Err(e) => debug!("connect {} failed: {e}", sock.display()),
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            });
        }
        (None, Some(file)) => file_loop(file.clone(), cfg.clone(), tx),
        (None, None) => warn!("suricata.enabled but no eve_socket/eve_file configured"),
    }
}

async fn socket_with_file_fallback(
    sock: PathBuf,
    file: PathBuf,
    cfg: Suricata,
    tx: UnboundedSender<Alert>,
) {
    // 给 Suricata 一点启动时间
    for _ in 0..5 {
        match tokio::net::UnixStream::connect(&sock).await {
            Ok(stream) => {
                info!("connected to Suricata eve socket {}", sock.display());
                read_socket(stream, &cfg, &tx).await;
                warn!("eve socket {} closed", sock.display());
                if file.exists() {
                    break;
                }
            }
            Err(e) => debug!("connect {} failed: {e}", sock.display()),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    warn!(
        "eve socket {} unavailable, fallback to tail {}",
        sock.display(),
        file.display()
    );
    file_loop(file, cfg, tx);
}

async fn read_socket(stream: tokio::net::UnixStream, cfg: &Suricata, tx: &UnboundedSender<Alert>) {
    let mut lines = tokio::io::BufReader::new(stream).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        parse_line(&line, cfg, tx);
    }
}

fn file_loop(path: PathBuf, cfg: Suricata, tx: UnboundedSender<Alert>) {
    std::thread::spawn(move || {
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                warn!("cannot open eve file {}: {e}", path.display());
                return;
            }
        };
        let mut reader = BufReader::new(file);
        // 只关心新增的行，跳到文件末尾
        let _ = reader.seek(SeekFrom::End(0));

        let mut line = String::new();
        loop {
            match reader.read_line(&mut line) {
                Ok(0) => {
                    line.clear();
                    std::thread::sleep(Duration::from_millis(200));
                }
                Ok(_) => {
                    parse_line(&line, &cfg, &tx);
                    line.clear();
                }
                Err(e) => {
                    debug!("eve file read error: {e}");
                    line.clear();
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
    });
}

fn parse_line(line: &str, cfg: &Suricata, tx: &UnboundedSender<Alert>) {
    let Ok(rec) = serde_json::from_str::<EveRecord>(line) else {
        return;
    };
    if rec.event_type != "alert" {
        return;
    }
    let Some(alert) = rec.alert else {
        return;
    };
    let Some(severity) = alert.severity else {
        return;
    };
    if severity > cfg.block_severity_max {
        return;
    }
    let Some(ip) = rec
        .src_ip
        .as_deref()
        .and_then(|s| s.parse::<IpAddr>().ok())
    else {
        return;
    };
    let _ = tx.send(Alert {
        ip,
        severity,
        signature: alert.signature.clone().unwrap_or_default(),
        block_seconds: if cfg.block_seconds == 0 {
            None
        } else {
            Some(cfg.block_seconds)
        },
    });
}
