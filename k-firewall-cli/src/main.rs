use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use k_firewall_common::api::BlockRequest;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Debug, Parser)]
struct Cli {
    /// daemon 的 Unix Domain Socket 路径
    #[clap(long, global = true, default_value = "/var/run/k-firewall.sock")]
    socket: PathBuf,
    /// API 密钥（与 daemon 配置 api_keys 匹配）；通过 HTTP 管理时必须提供
    #[clap(long, global = true, env = "K_FIREWALL_API_KEY")]
    api_key: Option<String>,
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// 运行状态
    Status,
    /// 流量统计
    Stats,
    /// 当前封禁的源 IP
    Blocked,
    /// 封禁一个源 IP
    Block {
        ip: String,
        /// 封禁秒数；缺省 = 永久
        #[clap(long)]
        seconds: Option<u64>,
        #[clap(long)]
        reason: Option<String>,
    },
    /// 解除封禁
    Unblock { ip: String },
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    let cli = Cli::parse();
    let (method, path, body) = match cli.cmd {
        Cmd::Status => ("GET", "/status", None),
        Cmd::Stats => ("GET", "/stats", None),
        Cmd::Blocked => ("GET", "/blocked", None),
        Cmd::Block {
            ip,
            seconds,
            reason,
        } => {
            let body = serde_json::to_vec(&BlockRequest {
                ip,
                seconds,
                reason,
            })?;
            ("POST", "/block", Some(body))
        }
        Cmd::Unblock { ip } => {
            let body = serde_json::to_vec(&BlockRequest {
                ip,
                seconds: None,
                reason: None,
            })?;
            ("POST", "/unblock", Some(body))
        }
    };

    let resp = request(&cli.socket, &cli.api_key, method, path, body).await?;
    print!("{resp}");
    Ok(ExitCode::SUCCESS)
}

/// 通过 Unix Domain Socket 发送一个 HTTP/1.1 请求并返回响应体（美化 JSON）。
async fn request(
    sock: &Path,
    api_key: &Option<String>,
    method: &str,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<String> {
    let mut stream = UnixStream::connect(sock)
        .await
        .with_context(|| format!("connect {}", sock.display()))?;

    let len = body.as_ref().map(|b| b.len()).unwrap_or(0);
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {len}\r\nConnection: close\r\n"
    );
    if body.is_some() {
        head.push_str("Content-Type: application/json\r\n");
    }
    if let Some(k) = api_key {
        head.push_str(&format!("X-API-Key: {k}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    if let Some(b) = body {
        stream.write_all(&b).await?;
    }
    stream.flush().await?;

    let mut reader = BufReader::new(&mut stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
    let status = status_line.split_whitespace().nth(1).unwrap_or("000");

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" {
            break;
        }
    }

    let mut body = String::new();
    reader.read_to_string(&mut body).await?;

    if status != "200" {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(e) = v.get("error") {
                bail!("HTTP {status}: {e}");
            }
        }
        bail!("HTTP {status}: {body}");
    }

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        Ok(serde_json::to_string_pretty(&v)? + "\n")
    } else {
        Ok(body)
    }
}
