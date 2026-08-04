//! k-firewalld：XDP/TC 数据面守护进程（内核 eBPF 程序 + 用户态管理 API）。
#![recursion_limit = "512"]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{info, warn};

mod api;
mod bridge;
mod config;
mod dhcp;
mod ebpf_loader;
mod multiwan;
mod nat;
mod netlink;
mod openapi;
mod persist;
mod qos;
mod stats;
mod suricata;
mod suricata_rules;

use api::AppState;
use config::Config;

#[derive(Debug, Parser)]
struct Opt {
    /// XDP 挂载网卡（覆盖配置文件）
    #[clap(short, long)]
    iface: Option<String>,
    /// 配置文件路径
    #[clap(short, long, default_value = "k-firewall.yaml")]
    config: PathBuf,
    /// 统计打印间隔（秒），覆盖配置文件
    #[clap(long)]
    stats_interval: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let opt = Opt::parse();
    let mut config = Config::load(&opt.config)?;
    if let Some(iface) = &opt.iface {
        config.interface = iface.clone();
    }
    config.normalize();
    if let Some(secs) = opt.stats_interval {
        config.stats_interval_secs = secs;
    }

    // 提升 memlock 上限（老内核未启用 memcg 计账时需要）
    raise_memlock();

    netlink::log_interfaces()?;

    // 透明/混合接口对：创建内核 bridge 承载 L2 转发（在挂 XDP 前完成，
    // 接口需要先脱离独立链路状态）。
    bridge::setup_transparent_bridges(&config)?;

    let mut handle = ebpf_loader::EbpfHandle::load_and_attach(&config)?;
    info!(
        "XDP attached to {} (default action {})",
        handle.ifaces().join(", "),
        config.default_action
    );

    let state = Arc::new(AppState::new(handle, config.clone(), Some(opt.config.clone()))?);

    // 恢复持久化的 Suricata 规则并重同步 eBPF 预过滤表。
    if let Err(e) = suricata_rules::restore(&state).await {
        warn!("failed to restore suricata rules: {e:#}");
    }

    // NAT：按配置声明式下发 masquerade 规则（独立 kfw_nat 表，启动 flush 幂等）。
    nat::sync_nat_rules(&config)?;

    // IPv6 NAT66（masquerade 出口）：独立 kfw_nat6 表，与 IPv4 隔离。
    nat::sync_nat6_rules(&config)?;

    // QoS 出口整形（HTB）：按 `qos.shaping` 配置下发 tc 规则。
    if !config.qos.shaping.is_empty() {
        if let Err(e) = qos::setup_shaping(&config) {
            warn!("QoS shaping setup failed: {e:#}");
        }
    }

    // DHCPv6 服务：对配置了 `dhcp6_server` 的 LAN 接口提供有状态地址分配。
    for h in dhcp::spawn_servers(&config) {
        let _ = h;
    }

    // REST API over Unix Domain Socket
    let api_path = config.daemon.unix_socket.clone();
    let api_path_display = api_path.clone();
    let state_api = state.clone();
    let api_task = tokio::spawn(async move {
        if let Err(e) = api::serve(&api_path, state_api).await {
            warn!("API server error: {e:#}");
        }
    });

    // REST API over TCP/HTTP（可选，`daemon.http_addr` 如 "0.0.0.0:8080"）
    if let Some(http_addr) = config.daemon.http_addr.clone() {
        let state_http = state.clone();
        tokio::spawn(async move {
            if let Err(e) = api::serve_http(&http_addr, state_http).await {
                warn!("HTTP API server error: {e:#}");
            }
        });
    }

    // Suricata 联动：告警 -> 自动封禁源 IP
    let (alert_tx, alert_rx) = mpsc::unbounded_channel();
    if config.suricata.enabled {
        suricata::spawn(&config.suricata, alert_tx);
    }
    let state_suri = state.clone();
    tokio::spawn(async move {
        let mut rx = alert_rx;
        while let Some(alert) = rx.recv().await {
            match state_suri
                .block(alert.ip, alert.block_seconds, alert.signature.clone())
                .await
            {
                Ok(()) => info!(
                    "auto-blocked {} (sev {}, reason {:?})",
                    alert.ip, alert.severity, alert.signature
                ),
                Err(e) => warn!("auto-block {} failed: {e:#}", alert.ip),
            }
        }
    });

    // 周期统计打印
    let state_stats = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(config.stats_interval_secs));
        loop {
            ticker.tick().await;
            match state_stats.read_stats().await {
                Ok(s) => stats::log(&s),
                Err(e) => warn!("read stats failed: {e:#}"),
            }
        }
    });

    // 封禁记录过期清理（同步删除内核 BLOCKED map 中的条目）
    let state_prune = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            state_prune.prune_expired().await;
        }
    });

    // 连接跟踪 / 分片流过期清理（按配置的超时从 CONNTRACK / FRAG_TRACK 移除）。
    if config.conntrack.enabled {
        let state_ct = state.clone();
        let ct_cfg = config.conntrack.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                if let Err(e) = state_ct.prune_conntrack(&ct_cfg).await {
                    warn!("prune conntrack failed: {e:#}");
                }
            }
        });
    }
    let state_frag = state.clone();
    let frag_timeout = config.fragment_timeout_secs;
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            if let Err(e) = state_frag.prune_frag_track(frag_timeout).await {
                warn!("prune frag track failed: {e:#}");
            }
        }
    });

    // P0：每源连接数 / 半开数周期校正（XDP 只增不减的场景由此处从 CONNTRACK 重算）。
    if config.conntrack.enabled {
        let state_reconcile = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                if let Err(e) = state_reconcile.reconcile_conn_counts().await {
                    warn!("reconcile conn counts failed: {e:#}");
                }
            }
        });
    }

    // 多 WAN 健康检查 + 故障切换 + 策略路由（可选）
    if config.multiwan.enabled {
        let cfg = config.clone();
        tokio::spawn(multiwan::run(cfg));
    }

    info!("k-firewalld ready (socket {})", api_path_display.display());

    signal::ctrl_c().await?;
    info!("received SIGINT, shutting down");
    api_task.abort();
    // 清理 nftables NAT 表（不残留）。
    nat::cleanup_nat_rules();
    nat::cleanup_nat6_rules();
    drop(state);
    Ok(())
}

fn raise_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        info!("setrlimit(RLIMIT_MEMLOCK) failed, ret = {ret}");
    }
}
