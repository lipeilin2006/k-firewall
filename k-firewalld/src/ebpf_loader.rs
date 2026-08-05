use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use anyhow::{Context as _, Result, anyhow, bail};
use aya::Ebpf;
use aya::maps::{
    Array, DevMap, HashMap, Map, MapData, PerCpuArray, RingBuf, lpm_trie::Key as LpmKey,
    lpm_trie::LpmTrie,
};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpMode};
use k_firewall_common::maps::{
    AlgExpect, CT_STATE_GENERIC, CT_STATE_ICMP, CT_STATE_MAX, CT_STATE_TCP_ESTABLISHED,
    CT_STATE_TCP_FIN_WAIT, CT_STATE_TCP_SYN_RECV, CT_STATE_TCP_SYN_SENT, CT_STATE_TCP_TIME_WAIT,
    CT_STATE_UDP, ConnLimit, CtValue, DnatKey, DnatValue, FAMILY_IPV4, FRAG_POLICY_DROP,
    FRAG_POLICY_INSPECT, FiveTuple, FragKey, IpKey, QosBucket, QosConfig, RateState,
    SESSION_BLOCKED, SESSION_DROP, SESSION_NEW, SessionEvent, VifConfig, VifKey, ZoneEntry,
};
use k_firewall_common::{
    BLOCKED_MARKER, CONFIG_DEFAULT_ACTION, CONFIG_FRAG_TIMEOUT, CONFIG_FRAGMENT_POLICY,
    CONFIG_FTP_ALG, CONFIG_QOS_COUNT, CONFIG_RA_FILTER, CONFIG_SURICATA_PREFILTER,
    CONFIG_SYN_BURST, CONFIG_SYN_MAX_HALFOPEN, CONFIG_SYN_RATE, CONFIG_ZONE_COUNT, Stats,
};
use serde::Deserialize;
use tokio::io::AsyncBufReadExt as _;
use tracing::{debug, info, warn};

use crate::config::{Config, Conntrack, SessionLog};

/// Suricata eve.json event types we care about.
#[derive(Debug, Deserialize)]
struct SuricataEvent {
    #[serde(rename = "event_type")]
    event_type: Option<String>,
    src_ip: Option<String>,
    #[serde(rename = "dest_ip")]
    dst_ip: Option<String>,
    src_port: Option<u16>,
    #[serde(rename = "dest_port")]
    dst_port: Option<u16>,
    proto: Option<String>,
    #[serde(rename = "app_proto")]
    app_proto: Option<String>,
    #[serde(rename = "alert")]
    alert: Option<SuricataAlert>,
    #[serde(rename = "flow")]
    flow: Option<SuricataFlow>,
    #[serde(rename = "ftp")]
    ftp: Option<SuricataFtp>,
    #[serde(rename = "tls")]
    tls: Option<SuricataTls>,
    #[serde(rename = "http")]
    http: Option<SuricataHttp>,
    #[serde(rename = "dns")]
    dns: Option<SuricataDns>,
}

/// Suricata `ftp` 事件：FTP 应用层命令/应答（含数据连接动态端口）。
#[derive(Debug, Deserialize)]
struct SuricataFtp {
    /// 命令，如 `PASV` / `PORT` / `EPSV` / `EPRT`。
    command: Option<String>,
    /// 主动/被动模式："active"（PORT/EPRT）或 "passive"（PASV/EPSV）。
    #[serde(rename = "mode")]
    mode: Option<String>,
    /// 数据连接端口（227 应答 / PORT 参数解析而来）。
    #[serde(rename = "dynamic_port")]
    dynamic_port: Option<u16>,
    /// 应答码，如 ["227"]。
    #[serde(rename = "completion_code")]
    completion_code: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct SuricataAlert {
    severity: Option<u8>,
    action: Option<String>,
    #[serde(rename = "signature_id")]
    signature_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SuricataFlow {
    #[serde(rename = "pkts_toserver")]
    pkts_toserver: Option<u64>,
    #[serde(rename = "pkts_toclient")]
    pkts_toclient: Option<u64>,
}

/// Suricata `tls` 事件：TLS 握手元数据（fingerprint = JA3/JA3S）。
#[derive(Debug, Default, Deserialize)]
struct SuricataTls {
    #[serde(rename = "fingerprint")]
    fingerprint: Option<String>,
    #[serde(rename = "sni")]
    sni: Option<String>,
    #[serde(rename = "version")]
    version: Option<String>,
    #[serde(rename = "ja3")]
    ja3: Option<String>,
}

/// Suricata `http` 事件：HTTP 事务元数据。
#[derive(Debug, Default, Deserialize)]
struct SuricataHttp {
    #[serde(rename = "hostname")]
    hostname: Option<String>,
    #[serde(rename = "http_user_agent")]
    http_user_agent: Option<String>,
    #[serde(rename = "http_method")]
    http_method: Option<String>,
    #[serde(rename = "url")]
    url: Option<String>,
    #[serde(rename = "status")]
    status: Option<u16>,
}

/// Suricata `dns` 事件：DNS 查询元数据。
#[derive(Debug, Default, Deserialize)]
struct SuricataDns {
    #[serde(rename = "type")]
    dtype: Option<String>,
    #[serde(rename = "query")]
    query: Option<String>,
    #[serde(rename = "rrname")]
    rrname: Option<String>,
    #[serde(rename = "rcode")]
    rcode: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Pass,
    Drop,
}

impl Action {
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "pass" => Ok(Action::Pass),
            "drop" => Ok(Action::Drop),
            other => bail!("unsupported action {other:?} (pass|drop)"),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Action::Pass => k_firewall_common::ACTION_PASS,
            Action::Drop => k_firewall_common::ACTION_DROP,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Pass => "pass",
            Action::Drop => "drop",
        }
    }
}

/// eBPF 程序与 map 的用户态句柄。
///
/// 链接由 `Ebpf` 对象持有，句柄析构时自动 detach。Suricata 规则头预过滤
/// 表（`SURICATA_RULES_*`）在加载时一次性取出并常驻句柄，供运行时全量重同步复用。
pub struct EbpfHandle {
    ebpf: Ebpf,
    ifaces: Vec<String>,
    /// Suricata 规则头预过滤 LpmTrie（IPv4，daemon 依据 WebAPI 添加的规则写入）。
    /// 4 张表对应 src/dst 通配形态，键布局见 `suricata_rules::SuriTuples`。
    suricata_rules_dst: LpmTrie<MapData, [u8; 13], u8>,
    suricata_rules_dst_any: LpmTrie<MapData, [u8; 9], u8>,
    suricata_rules_src: LpmTrie<MapData, [u8; 13], u8>,
    suricata_rules_src_any: LpmTrie<MapData, [u8; 9], u8>,
    /// Suricata eve 事件 → 会话元数据（app 协议 / TLS 指纹 / HTTP / DNS），
    /// 由 eve 监听任务写入，`dump_sessions` 读取合并。key 为正向五元组。
    session_meta: Arc<std::sync::Mutex<std::collections::HashMap<FiveTuple, SessionMeta>>>,
    /// 各 `CT_STATE_*` 状态超时（秒），加载时从配置写入；供 `dump_sessions`
    /// 计算 `expire_in_secs` 等只读字段（与 `prune_conntrack` 的 cfg 保持同一来源）。
    ct_timeouts: [u32; CT_STATE_MAX],
    /// QoS 分类配置数组（`QOS_CLASSES`，长度固定 `QOS_MAX`）：运行时全量重同步复用。
    qos_classes: Array<MapData, QosConfig>,
    /// QoS 每类入口限速桶（`QOS_BUCKETS`，per-CPU）。
    qos_buckets: PerCpuArray<MapData, QosBucket>,
    /// Zone 策略数组（`ZONE`，长度固定 `ZONE_MAX`）：运行时按 id 顺序热同步。
    zone: Array<MapData, ZoneEntry>,
    /// 源 IP 速率限制（`RATE_LIMITS`，LRU 哈希）：运行时热同步。
    rate_limits: HashMap<MapData, IpKey, RateState>,
    /// 每源并发连接数上限（`CONN_LIMITS`）：运行时热同步。
    conn_limits: HashMap<MapData, IpKey, ConnLimit>,
    /// 端口转发 DNAT（`DNAT_RULES`）：运行时热同步。
    dnat_rules: HashMap<MapData, DnatKey, DnatValue>,
}

/// 会话的应用层元数据（来自 Suricata eve 事件）。
#[derive(Debug, Clone, Default)]
struct SessionMeta {
    app_proto: Option<String>,
    tls_fingerprint: Option<String>,
    tls_sni: Option<String>,
    http_host: Option<String>,
    http_user_agent: Option<String>,
    dns_query: Option<String>,
    app_info: Option<String>,
    /// 最近一次合并的时刻（CLOCK_MONOTONIC，ns）；用于孤儿条目 TTL 清扫。
    last_updated: u64,
}

/// 解析 XDP 挂载模式配置。
pub fn xdp_mode(s: &str) -> Result<XdpMode> {
    Ok(match s {
        "generic" => XdpMode::Skb,
        "native" | "driver" => XdpMode::Driver,
        "hardware" => XdpMode::Hardware,
        "auto" | "default" => XdpMode::default(),
        other => bail!("unsupported xdp_mode {other:?} (generic|native|hardware|auto)"),
    })
}

/// 启动 eBPF 日志转发任务：按程序 id 定位该程序自己的 AYA_LOGS RingBuf。
fn spawn_logger(program_id: u32) {
    match aya_log::EbpfLogger::init_from_id(program_id) {
        Ok(logger) => {
            tokio::spawn(async move {
                let mut logger = match tokio::io::unix::AsyncFd::with_interest(
                    logger,
                    tokio::io::Interest::READABLE,
                ) {
                    Ok(fd) => fd,
                    Err(_) => return,
                };
                loop {
                    let Ok(mut guard) = logger.readable_mut().await else {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    };
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
        Err(e) => warn!("failed to init eBPF logger for program {program_id}: {e}"),
    }
}

/// 将 `SESSION_LOG` RingBuf 中的事件格式化为日志行并转发（可选 syslog）。
fn consume_session_events(
    rb: &mut RingBuf<MapData>,
    to_syslog: Option<&UdpSocket>,
    syslog_server: &SocketAddr,
    hostname: &str,
) {
    while let Some(item) = rb.next() {
        let data: &[u8] = &item;
        if data.len() != std::mem::size_of::<SessionEvent>() {
            warn!("session log: bad event size {}", data.len());
            continue;
        }
        let ev: SessionEvent =
            unsafe { std::ptr::read_unaligned(data.as_ptr() as *const SessionEvent) };
        let src: IpAddr = if ev.family == FAMILY_IPV4 {
            IpAddr::V4(Ipv4Addr::new(
                ev.src_ip[0],
                ev.src_ip[1],
                ev.src_ip[2],
                ev.src_ip[3],
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(ev.src_ip))
        };
        let dst: IpAddr = if ev.family == FAMILY_IPV4 {
            IpAddr::V4(Ipv4Addr::new(
                ev.dst_ip[0],
                ev.dst_ip[1],
                ev.dst_ip[2],
                ev.dst_ip[3],
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(ev.dst_ip))
        };
        let action = match ev.action {
            SESSION_NEW => "NEW",
            SESSION_DROP => "DROP",
            SESSION_BLOCKED => "BLOCKED",
            _ => "?",
        };
        let proto = proto_name(ev.proto);
        let line = format!(
            "SESSION action={} family={} proto={} ifindex={} src={}:{} dst={}:{}",
            action,
            if ev.family == FAMILY_IPV4 {
                "ipv4"
            } else {
                "ipv6"
            },
            proto,
            ev.ifindex,
            src,
            ev.src_port,
            dst,
            ev.dst_port,
        );
        if let Some(sock) = to_syslog {
            let _ = sock.send_to(
                format!("<134>1 {hostname} k-firewalld - - - {line}").as_bytes(),
                syslog_server,
            );
        }
        info!("{}", line);
    }
}

fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmp6",
        _ => "unknown",
    }
}

/// 启动 SESSION_LOG RingBuf 消费任务（会话日志）。
fn spawn_session_logger(map: Map, cfg: &SessionLog) {
    let Ok(rb) = RingBuf::<MapData>::try_from(map) else {
        warn!("failed to take SESSION_LOG RingBuf");
        return;
    };
    let to_syslog = if cfg.enabled && cfg.syslog_enabled {
        let server: SocketAddr = match cfg.syslog_server.parse() {
            Ok(SocketAddr::V4(a)) => SocketAddr::new(IpAddr::V4(*a.ip()), cfg.syslog_port),
            Ok(a) => SocketAddr::new(a.ip(), cfg.syslog_port),
            Err(_) => {
                warn!(
                    "session syslog: invalid server {:?}, falling back to 127.0.0.1",
                    cfg.syslog_server
                );
                SocketAddr::from(([127, 0, 0, 1], cfg.syslog_port))
            }
        };
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => Some((s, server)),
            Err(e) => {
                warn!("session syslog: bind failed: {e}");
                None
            }
        }
    } else {
        None
    };
    let hostname = match std::fs::read_to_string("/proc/sys/kernel/hostname") {
        Ok(h) => h.trim().to_string(),
        Err(_) => "k-firewall".into(),
    };
    tokio::spawn(async move {
        let mut rb =
            match tokio::io::unix::AsyncFd::with_interest(rb, tokio::io::Interest::READABLE) {
                Ok(fd) => fd,
                Err(_) => return,
            };
        loop {
            let Ok(mut guard) = rb.readable_mut().await else {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            };
            match &to_syslog {
                Some((sock, server)) => {
                    consume_session_events(guard.get_inner_mut(), Some(sock), server, &hostname)
                }
                None => consume_session_events(
                    guard.get_inner_mut(),
                    None,
                    &SocketAddr::from(([0, 0, 0, 0], 0)),
                    &hostname,
                ),
            }
            guard.clear_ready();
        }
    });
}

/// 通过 /sys/class/net 解析接口索引。
pub(crate) fn if_index(name: &str) -> Option<i32> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// CLOCK_MONOTONIC 纳秒（与 eBPF `bpf_ktime_get_ns` 同一时钟基）。
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec.max(0) as u64) * 1_000_000_000 + (ts.tv_nsec.max(0) as u64)
}

/// 会话稳定 ID：五元组键的完整十六进制编码（family+proto+src16+dst16+ports）。
fn session_id_full(key: &FiveTuple) -> String {
    let mut s = String::with_capacity(76);
    let push = |s: &mut String, b: u8| {
        s.push_str(&format!("{b:02x}"));
    };
    push(&mut s, key.family);
    push(&mut s, key.proto);
    for i in 0..16 {
        push(&mut s, key.src_ip[i]);
    }
    for i in 0..16 {
        push(&mut s, key.dst_ip[i]);
    }
    for p in key.src_port.to_be_bytes() {
        push(&mut s, p);
    }
    for p in key.dst_port.to_be_bytes() {
        push(&mut s, p);
    }
    s
}

/// 从完整会话 ID 还原五元组（`session_id_full` 的逆操作）。
fn session_key_from_full_id(id: &str) -> Option<FiveTuple> {
    if id.len() != 76 {
        return None;
    }
    let hex = |i: usize| u8::from_str_radix(&id[i * 2..i * 2 + 2], 16).ok();
    let mut src_ip = [0u8; 16];
    let mut dst_ip = [0u8; 16];
    for i in 0..16 {
        src_ip[i] = hex(2 + i)?;
        dst_ip[i] = hex(18 + i)?;
    }
    let src_port = u16::from_be_bytes([hex(34)?, hex(35)?]);
    let dst_port = u16::from_be_bytes([hex(36)?, hex(37)?]);
    Some(FiveTuple {
        family: hex(0)?,
        proto: hex(1)?,
        _pad: [0; 2],
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        _pad2: 0,
    })
}

/// 用户态连接条目过期判断（与 eBPF 侧 `ct_expired` 同一规则）。
fn ct_expired(v: &CtValue, now: u64, timeouts: &[u32; CT_STATE_MAX]) -> bool {
    let timeout_secs = timeouts[v.state as usize];
    if timeout_secs == 0 {
        return false;
    }
    now > v.last_seen && now - v.last_seen > (timeout_secs as u64) * 1_000_000_000
}

impl EbpfHandle {
    /// 加载 eBPF 目标文件、初始化日志、挂载 XDP 到所有物理网卡并写入 map。
    pub fn load_and_attach(config: &Config) -> Result<Self> {
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/k-firewall-ebpf"
        )))?;

        let program: &mut Xdp = ebpf
            .program_mut("k_firewall")
            .ok_or_else(|| anyhow!("XDP program k_firewall not found"))?
            .try_into()?;
        program.load()?;
        // eBPF 日志转发：按程序 id 读取该程序自己的 AYA_LOGS RingBuf。
        spawn_logger(program.info()?.id());

        let mode = xdp_mode(&config.xdp_mode)?;
        let mut ifaces: Vec<String> = Vec::new();
        for phy in config.attach_ifaces() {
            // 确保网卡处于 UP 状态（IP 地址等其余配置假定已由外部完成）
            match if_index(&phy) {
                Some(idx) => {
                    let ret = unsafe { aya::sys::netlink_set_link_up(idx) };
                    if let Err(e) = ret {
                        warn!("failed to set {} up: {e}", phy);
                    }
                }
                None => warn!("cannot resolve ifindex for {}", phy),
            }
            program.attach(&phy, mode).with_context(|| {
                format!(
                    "failed to attach XDP to {} (mode {:?}; try XdpMode::Generic)",
                    phy, mode
                )
            })?;
            info!("attached XDP to {} (mode {:?})", phy, mode);
            ifaces.push(phy);
        }
        if ifaces.is_empty() {
            bail!("no configured interface resolved");
        }

        // NAT 感知回程：对 masquerade 出口（IPv4 / IPv6）挂 TC Egress 学习程序
        // （POSTROUTING 之后执行，可看到 NAT 后五元组，翻转写入 CONNTRACK 供
        // XDP 回程快速放行）。
        let mut tc_ifaces: Vec<String> = config.nat_egress_ifaces();
        for p in config.nat6_egress_ifaces() {
            if !tc_ifaces.contains(&p) {
                tc_ifaces.push(p);
            }
        }
        if !tc_ifaces.is_empty() {
            let tc: &mut SchedClassifier = ebpf
                .program_mut("kfw_tc_egress")
                .ok_or_else(|| anyhow!("TC program kfw_tc_egress not found"))?
                .try_into()?;
            tc.load()?;
            // TC 程序独立的 AYA_LOGS map，需单独注册日志读取端。
            spawn_logger(tc.info()?.id());
            for phy in tc_ifaces {
                // 确保 clsact qdisc 存在（netlink 路径需要；TCX 路径忽略）。
                match std::process::Command::new("tc")
                    .args(["qdisc", "add", "dev", &phy, "clsact"])
                    .status()
                {
                    Ok(_) => {}
                    Err(e) => warn!("tc qdisc add clsact on {phy} failed (may already exist): {e}"),
                }
                tc.attach(&phy, TcAttachType::Egress).with_context(|| {
                    format!("failed to attach TC egress to {phy} (need tc qdisc clsact)")
                })?;
                info!("attached TC egress to {phy}");
            }
        }

        let mut config_map: Array<_, u32> =
            Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map not found")?)?;
        config_map.set(
            CONFIG_DEFAULT_ACTION,
            config.default_action().as_u8() as u32,
            0,
        )?;
        // 分片策略 / RA 过滤 / QoS 分类数 / 分片流超时。
        let frag_policy = match config.fragment_policy.as_str() {
            "drop" => FRAG_POLICY_DROP,
            "inspect" => FRAG_POLICY_INSPECT,
            _ => k_firewall_common::maps::FRAG_POLICY_PASS,
        };
        config_map.set(CONFIG_FRAGMENT_POLICY, frag_policy as u32, 0)?;
        config_map.set(
            CONFIG_RA_FILTER,
            if config.ipv6.ra_filter { 1 } else { 0 },
            0,
        )?;
        let qos_count = config
            .qos
            .classes
            .len()
            .min(k_firewall_common::maps::QOS_MAX as usize) as u8;
        config_map.set(CONFIG_QOS_COUNT, qos_count as u32, 0)?;
        config_map.set(
            CONFIG_FRAG_TIMEOUT,
            config.fragment_timeout_secs.min(u8::MAX as u64) as u32,
            0,
        )?;
        // SYN Flood 防护：每源 IP 新建连接速率（pps，0 = 关闭）+ 突发 + 半开上限。
        let syn = &config.syn_flood;
        config_map.set(CONFIG_SYN_RATE, syn.rate_pps, 0)?;
        config_map.set(CONFIG_SYN_BURST, syn.burst, 0)?;
        config_map.set(CONFIG_SYN_MAX_HALFOPEN, syn.max_half_open, 0)?;
        // FTP ALG 开关。
        config_map.set(
            CONFIG_FTP_ALG,
            if config.alg.ftp_enabled { 1 } else { 0 },
            0,
        )?;
        // Suricata 规则头预过滤：初始关闭（由运行时规则同步按需开启）。
        config_map.set(CONFIG_SURICATA_PREFILTER, 0, 0)?;

        // 连接跟踪每状态超时。
        let mut ct_timeouts: Array<_, u32> = Array::try_from(
            ebpf.take_map("CT_TIMEOUTS")
                .context("CT_TIMEOUTS map not found")?,
        )?;
        let timeouts = config.conntrack.timeouts();
        for (i, t) in timeouts.iter().enumerate() {
            ct_timeouts.set(i as u32, *t, 0)?;
        }
        info!(
            "conntrack enabled={} timeouts={:?}",
            config.conntrack.enabled, timeouts
        );

        // QoS：分类配置 + 入口限速桶（句柄常驻，运行时热同步复用）。
        let mut qos_classes: Array<_, QosConfig> = Array::try_from(
            ebpf.take_map("QOS_CLASSES")
                .context("QOS_CLASSES map not found")?,
        )?;
        for (i, entry) in config.qos_entries().iter().enumerate() {
            qos_classes.set(i as u32, *entry, 0)?;
            info!(
                "QOS[{}] ifindex={} proto={} sport={} dport={} dscp={} rate={} burst={}",
                i,
                entry.ingress_ifindex,
                entry.proto,
                entry.src_port,
                entry.dst_port,
                entry.dscp,
                entry.rate_bps,
                entry.burst_bytes
            );
        }
        let qos_buckets: PerCpuArray<_, QosBucket> = PerCpuArray::try_from(
            ebpf.take_map("QOS_BUCKETS")
                .context("QOS_BUCKETS map not found")?,
        )?;

        // 下发 VIF_MAP 与 REDIRECT_DEV。
        let mut vif_map: HashMap<_, VifKey, VifConfig> =
            HashMap::try_from(ebpf.take_map("VIF_MAP").context("VIF_MAP map not found")?)?;
        let mut dev_map: DevMap<_> = DevMap::try_from(
            ebpf.take_map("REDIRECT_DEV")
                .context("REDIRECT_DEV map not found")?,
        )?;
        // 本机接口 IP 集合（hybrid/route "目标为本机" 判断）。
        let mut local_ips: HashMap<_, IpKey, u8> = HashMap::try_from(
            ebpf.take_map("LOCAL_IPS")
                .context("LOCAL_IPS map not found")?,
        )?;
        let vifs = config.vifs();
        for (phy, vlan_id, vcfg) in vifs.iter() {
            let idx =
                if_index(phy).with_context(|| format!("cannot resolve ifindex for {}", phy))?;
            let key = VifKey {
                phy_ifindex: idx as u32,
                vlan_id: *vlan_id,
                _pad: 0,
            };
            vif_map.insert(key, *vcfg, 0)?;
            dev_map.set(vcfg.vif_id as u32, idx as u32, None, 0)?;
            info!(
                "VIF {} ifindex={} vlan={} mode={} role={} peer={}",
                phy, idx, vlan_id, vcfg.mode, vcfg.role, vcfg.peer_vif_id
            );
        }
        for ifc in &config.interfaces {
            if let Some(addr) = ifc.address {
                let key = IpKey::from_ipv4(u32::from(addr));
                local_ips.insert(key, 1, 0)?;
                info!("local IP {} on {}", addr, ifc.name);
            }
        }

        // 下发 Zone 策略（有序数组）：按配置顺序（等价 id 升序）写入 `ZONE`，
        // eBPF 从 0 起顺序遍历、首匹配生效（id 顺序即执行顺序）。
        let mut zone: Array<_, ZoneEntry> =
            Array::try_from(ebpf.take_map("ZONE").context("ZONE map not found")?)?;
        let zone_entries = config.zone_entries();
        // 数组上限 ZONE_MAX：配置超出时截断加载，避免 set 越界失败；数量以实际写入为准。
        for (i, (phy, dst_net, prefix_len, action)) in
            zone_entries.iter().take(k_firewall_common::maps::ZONE_MAX as usize).enumerate()
        {
            let idx = if_index(&phy)
                .with_context(|| format!("zone: cannot resolve ifindex for {}", phy))?;
            zone.set(
                i as u32,
                ZoneEntry::from_ipv4(idx as u32, *dst_net, *prefix_len as u8, *action),
                0,
            )?;
            info!(
                "ZONE[{}] src={} (ifindex={}) dst_net={:?}/{} action={}",
                i, phy, idx, dst_net, prefix_len, action
            );
        }
        if zone_entries.len() > k_firewall_common::maps::ZONE_MAX as usize {
            warn!(
                "zone_entries ({} entries) exceeds ZONE_MAX ({}), truncating to {}",
                zone_entries.len(),
                k_firewall_common::maps::ZONE_MAX,
                k_firewall_common::maps::ZONE_MAX
            );
        }
        {
            // 重新获取 CONFIG map：避免跨多个 take_map 的借用冲突。
            let mut config_map: Array<_, u32> = Array::try_from(
                ebpf.map_mut("CONFIG").context("CONFIG map not found")?,
            )?;
            config_map.set(
                CONFIG_ZONE_COUNT,
                zone_entries.len().min(k_firewall_common::maps::ZONE_MAX as usize) as u32,
                0,
            )?;
        }

        // 下发 DNAT 规则（端口转发）：key=(WAN IP:端口, proto) -> 内部服务器。
        // 句柄常驻，运行时热同步（WebAPI /nat/rules 增删改）复用。
        let mut dnat_rules: HashMap<_, DnatKey, DnatValue> = HashMap::try_from(
            ebpf.take_map("DNAT_RULES")
                .context("DNAT_RULES map not found")?,
        )?;
        for (i, dnat) in config.nat_rules.iter().enumerate() {
            let key = DnatKey::from_ipv4(
                u32::from(dnat.dst_ip),
                dnat.dst_port.to_be(),
                dnat.proto_u8().expect("config validated"),
            );
            let value = DnatValue::from_ipv4(u32::from(dnat.to_ip), dnat.to_port.to_be());
            dnat_rules.insert(key, value, 0)?;
            info!(
                "DNAT[{}] {}:{} {} -> {}:{}",
                i, dnat.dst_ip, dnat.dst_port, dnat.proto, dnat.to_ip, dnat.to_port
            );
        }

        // 源 IP 速率限制：预填令牌桶条目（LRU map，未配置的源 IP 不设限速）。
        // 句柄常驻，运行时热同步（WebAPI /security/rate-limits）复用。
        let mut rate_limits: HashMap<_, IpKey, RateState> = HashMap::try_from(
            ebpf.take_map("RATE_LIMITS")
                .context("RATE_LIMITS map not found")?,
        )?;
        for rl in &config.rate_limit_rules {
            let key = match rl.src_ip {
                IpAddr::V4(a) => IpKey::from_ipv4(u32::from(a)),
                IpAddr::V6(a) => IpKey::from_ipv6(a.octets()),
            };
            rate_limits.insert(key, RateState::new(rl.rate, rl.burst), 0)?;
            info!(
                "RATE LIMIT {}: {} pps burst {}",
                rl.src_ip, rl.rate, rl.burst
            );
        }

        // 每源 IP 并发连接数上限：预填 CONN_LIMITS（未配置的源 IP 不限制）。
        // 句柄常驻，运行时热同步（WebAPI /security/conn-limits）复用。
        let mut conn_limits: HashMap<_, IpKey, ConnLimit> = HashMap::try_from(
            ebpf.take_map("CONN_LIMITS")
                .context("CONN_LIMITS map not found")?,
        )?;
        for cl in &config.conn_limits {
            let key = match cl.src_ip {
                IpAddr::V4(a) => IpKey::from_ipv4(u32::from(a)),
                IpAddr::V6(a) => IpKey::from_ipv6(a.octets()),
            };
            conn_limits.insert(
                key,
                ConnLimit {
                    max_conns: cl.max_conns,
                },
                0,
            )?;
            info!("CONN LIMIT {}: max {} conns", cl.src_ip, cl.max_conns);
        }

        // 会话日志：取出 SESSION_LOG RingBuf，若启用则启动异步消费任务。
        if config.session_log.enabled {
            match ebpf
                .take_map("SESSION_LOG")
                .context("SESSION_LOG map not found")
            {
                Ok(map) => {
                    spawn_session_logger(map, &config.session_log);
                    info!(
                        "session logging enabled (syslog: {})",
                        config.session_log.syslog_enabled
                    );
                }
                Err(e) => warn!("session logging skipped: {e}"),
            }
        } else {
            info!("session logging disabled");
        }

        // Suricata eve.sock 监听：解析 Suricata 事件并更新 SURICATA_ALLOW_MAP
        // （双向流量五元组放行）、ALG_EXPECT（FTP 数据连接预期）与会话元数据。
        // 封禁由 suricata.rs 经 AppState::block 完成。
        let session_meta: Arc<std::sync::Mutex<std::collections::HashMap<FiveTuple, SessionMeta>>> =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        if let Err(e) = spawn_suricata_listener(
            &mut ebpf,
            &config.suricata,
            config.alg.ftp_enabled,
            session_meta.clone(),
        ) {
            warn!("suricata listener skipped: {e}");
        }

        // Suricata 规则头预过滤表常驻句柄：运行时全量重同步复用，避免重复 take_map。
        let suricata_rules_dst: LpmTrie<MapData, [u8; 13], u8> = LpmTrie::try_from(
            ebpf.take_map("SURICATA_RULES_DST")
                .context("SURICATA_RULES_DST map not found")?,
        )?;
        let suricata_rules_dst_any: LpmTrie<MapData, [u8; 9], u8> = LpmTrie::try_from(
            ebpf.take_map("SURICATA_RULES_DST_ANY")
                .context("SURICATA_RULES_DST_ANY map not found")?,
        )?;
        let suricata_rules_src: LpmTrie<MapData, [u8; 13], u8> = LpmTrie::try_from(
            ebpf.take_map("SURICATA_RULES_SRC")
                .context("SURICATA_RULES_SRC map not found")?,
        )?;
        let suricata_rules_src_any: LpmTrie<MapData, [u8; 9], u8> = LpmTrie::try_from(
            ebpf.take_map("SURICATA_RULES_SRC_ANY")
                .context("SURICATA_RULES_SRC_ANY map not found")?,
        )?;
        // 初始关闭规则头预过滤已在 config_map 阶段写入。

        // QoS 分类/限速桶常驻句柄：运行时热同步（WebAPI 增删改）复用。
        // 复用 load 阶段 take 的 QoS 常驻句柄（QOS_CLASSES / QOS_BUCKETS），
        // 供运行时 `sync_qos_classes` 热同步。

        Ok(Self {
            ebpf,
            ifaces,
            suricata_rules_dst,
            suricata_rules_dst_any,
            suricata_rules_src,
            suricata_rules_src_any,
            session_meta,
            ct_timeouts: timeouts,
            qos_classes,
            qos_buckets,
            zone,
            rate_limits,
            conn_limits,
            dnat_rules,
        })
    }

    pub fn ifaces(&self) -> &[String] {
        &self.ifaces
    }

    /// 全量同步 Suricata 规则头预过滤表：清空 4 张 `SURICATA_RULES_*` 后写入全部
    /// 元组（IPv4，值固定 1 = 该流需要 DPI），并按 `prefilter`（配置开启 && 有规则）
    /// 设置 `CONFIG_SURICATA_PREFILTER`。
    pub fn sync_suricata_rules(
        &mut self,
        tuples: &crate::suricata_rules::SuriTuples,
        prefilter: bool,
    ) -> Result<()> {
        // 原子重同步：先关闭预过滤开关，再清空/重写 4 张规则表，最后按新状态
        // 恢复开关，避免重写窗口内新建流命中半新半旧的表产生误放/误丢。
        let mut config_map: Array<_, u32> = Array::try_from(
            self.ebpf
                .map_mut("CONFIG")
                .context("CONFIG map not found")?,
        )?;
        config_map.set(CONFIG_SURICATA_PREFILTER, 0, 0)?;
        clear_lpm(&mut self.suricata_rules_dst);
        clear_lpm(&mut self.suricata_rules_dst_any);
        clear_lpm(&mut self.suricata_rules_src);
        clear_lpm(&mut self.suricata_rules_src_any);
        for k in &tuples.dst {
            self.suricata_rules_dst.insert(k, 1, 0)?;
        }
        for k in &tuples.dst_any {
            self.suricata_rules_dst_any.insert(k, 1, 0)?;
        }
        for k in &tuples.src {
            self.suricata_rules_src.insert(k, 1, 0)?;
        }
        for k in &tuples.src_any {
            self.suricata_rules_src_any.insert(k, 1, 0)?;
        }
        let enabled = prefilter && !tuples.is_empty();
        config_map.set(CONFIG_SURICATA_PREFILTER, if enabled { 1 } else { 0 }, 0)?;
        info!(
            "SURICATA_RULES synced: {} tuples (dst={} dst_any={} src={} src_any={}), prefilter={}",
            tuples.len(),
            tuples.dst.len(),
            tuples.dst_any.len(),
            tuples.src.len(),
            tuples.src_any.len(),
            enabled
        );
        Ok(())
    }

    /// 全量同步 QoS 分类：清空 `QOS_CLASSES` 后写入全部条目，并更新
    /// `CONFIG_QOS_COUNT`（控制 eBPF 遍历数量）。`QOS_BUCKETS` 桶按索引
    /// 复用，由 eBPF 侧 `apply_qos` 以 count 为界访问，无需显式清零。
    pub fn sync_qos_classes(&mut self, entries: &[QosConfig]) -> Result<()> {
        let count = entries.len().min(k_firewall_common::maps::QOS_MAX as usize);
        // 原子重同步：先停用遍历（COUNT=0），避免 eBPF 在清空/写入期间读到
        // 半新半旧的分类条目造成错误限速；全部写完后恢复 COUNT。
        let mut config_map: Array<_, u32> = Array::try_from(
            self.ebpf
                .map_mut("CONFIG")
                .context("CONFIG map not found")?,
        )?;
        config_map.set(CONFIG_QOS_COUNT, 0, 0)?;
        // 再清空整张表（写入零值），避免残留旧条目被 eBPF 遍历。
        let zero = QosConfig {
            ingress_ifindex: 0,
            proto: 0,
            _pad: [0; 3],
            src_port: 0,
            dst_port: 0,
            dscp: 0,
            _pad2: [0; 3],
            rate_bps: 0,
            burst_bytes: 0,
        };
        for i in 0..k_firewall_common::maps::QOS_MAX {
            self.qos_classes.set(i, zero, 0)?;
        }
        for (i, entry) in entries.iter().enumerate().take(count) {
            self.qos_classes.set(i as u32, *entry, 0)?;
        }
        config_map.set(CONFIG_QOS_COUNT, count as u32, 0)?;
        info!(
            "QOS synced: {} classes (max {}), CONFIG_QOS_COUNT={}",
            count,
            k_firewall_common::maps::QOS_MAX,
            count
        );
        Ok(())
    }

    /// 全量同步 Zone 策略：按传入顺序（id 升序）写入 `ZONE` 数组并更新
    /// `CONFIG_ZONE_COUNT`。原子重同步：先置 COUNT=0 停用遍历，清空数组后
    /// 写入全部条目，最后恢复 COUNT，避免 eBPF 读到半新半旧的策略。
    pub fn sync_zone_policies(&mut self, entries: &[ZoneEntry]) -> Result<()> {
        let count = entries.len().min(k_firewall_common::maps::ZONE_MAX as usize);
        let mut config_map: Array<_, u32> = Array::try_from(
            self.ebpf
                .map_mut("CONFIG")
                .context("CONFIG map not found")?,
        )?;
        config_map.set(CONFIG_ZONE_COUNT, 0, 0)?;
        let zero = ZoneEntry::from_ipv4(0, 0, 0, k_firewall_common::DEFAULT_ACTION);
        for i in 0..k_firewall_common::maps::ZONE_MAX {
            self.zone.set(i, zero, 0)?;
        }
        for (i, entry) in entries.iter().enumerate().take(count) {
            self.zone.set(i as u32, *entry, 0)?;
        }
        config_map.set(CONFIG_ZONE_COUNT, count as u32, 0)?;
        info!(
            "ZONE synced: {} entries (max {}), CONFIG_ZONE_COUNT={}",
            count,
            k_firewall_common::maps::ZONE_MAX,
            count
        );
        Ok(())
    }

    /// 全量同步源 IP 速率限制：清空 `RATE_LIMITS` 后写入全部条目。
    ///
    /// 原子重同步：先遍历清空旧条目，再逐个插入（LRU 表，key 唯一）。
    pub fn sync_rate_limit_entries(&mut self, entries: &[(IpKey, u32, u32)]) -> Result<()> {
        let keys: Vec<IpKey> = self.rate_limits.keys().filter_map(|r| r.ok()).collect();
        for k in &keys {
            let _ = self.rate_limits.remove(k);
        }
        for (key, rate, burst) in entries {
            self.rate_limits.insert(*key, RateState::new(*rate, *burst), 0)?;
        }
        info!("RATE_LIMITS synced: {} entries", entries.len());
        Ok(())
    }

    /// 全量同步每源并发连接数上限：清空 `CONN_LIMITS` 后写入全部条目。
    pub fn sync_conn_limits(&mut self, entries: &[(IpKey, u32)]) -> Result<()> {
        let keys: Vec<IpKey> = self.conn_limits.keys().filter_map(|r| r.ok()).collect();
        for k in &keys {
            let _ = self.conn_limits.remove(k);
        }
        for (key, max_conns) in entries {
            self.conn_limits.insert(
                *key,
                ConnLimit {
                    max_conns: *max_conns,
                },
                0,
            )?;
        }
        info!("CONN_LIMITS synced: {} entries", entries.len());
        Ok(())
    }

    /// 全量同步 DNAT 端口转发规则：清空 `DNAT_RULES` 后写入全部条目。
    pub fn sync_dnat_rules(&mut self, entries: &[(DnatKey, DnatValue)]) -> Result<()> {
        let keys: Vec<DnatKey> = self.dnat_rules.keys().filter_map(|r| r.ok()).collect();
        for k in &keys {
            let _ = self.dnat_rules.remove(k);
        }
        for (key, value) in entries {
            self.dnat_rules.insert(*key, *value, 0)?;
        }
        info!("DNAT_RULES synced: {} entries", entries.len());
        Ok(())
    }

    /// 同步 SYN Flood 全局防护配置（`CONFIG_SYN_*` 槽位）。
    pub fn sync_syn_flood(&mut self, rate_pps: u32, burst: u32, max_half_open: u32) -> Result<()> {
        let mut config_map: Array<_, u32> = Array::try_from(
            self.ebpf
                .map_mut("CONFIG")
                .context("CONFIG map not found")?,
        )?;
        config_map.set(CONFIG_SYN_RATE, rate_pps, 0)?;
        config_map.set(CONFIG_SYN_BURST, burst, 0)?;
        config_map.set(CONFIG_SYN_MAX_HALFOPEN, max_half_open, 0)?;
        info!(
            "SYN_FLOOD synced: rate={} burst={} half_open={}",
            rate_pps, burst, max_half_open
        );
        Ok(())
    }

    /// 封禁一个源 IP（IPv4 / IPv6）。过期清理由 daemon 的 prune 任务负责从 map 中移除。
    pub fn block(&mut self, ip: IpAddr) -> Result<()> {
        let mut map: HashMap<_, IpKey, u64> = HashMap::try_from(
            self.ebpf
                .map_mut("BLOCKED")
                .context("BLOCKED map not found")?,
        )?;
        let key = match ip {
            IpAddr::V4(a) => IpKey::from_ipv4(u32::from(a)),
            IpAddr::V6(a) => IpKey::from_ipv6(a.octets()),
        };
        map.insert(key, BLOCKED_MARKER, 0)?;
        Ok(())
    }

    pub fn unblock(&mut self, ip: IpAddr) -> Result<()> {
        let mut map: HashMap<_, IpKey, u64> = HashMap::try_from(
            self.ebpf
                .map_mut("BLOCKED")
                .context("BLOCKED map not found")?,
        )?;
        let key = match ip {
            IpAddr::V4(a) => IpKey::from_ipv4(u32::from(a)),
            IpAddr::V6(a) => IpKey::from_ipv6(a.octets()),
        };
        map.remove(&key)?;
        Ok(())
    }

    /// 聚合读取 `STATS` per-CPU map。
    pub fn read_stats(&mut self) -> Result<Stats> {
        let map: PerCpuArray<_, Stats> =
            PerCpuArray::try_from(self.ebpf.map_mut("STATS").context("STATS map not found")?)?;
        let values = map.get(&0, 0)?;
        let mut total = Stats {
            packets: 0,
            passed: 0,
            dropped: 0,
            blocked: 0,
        };
        for v in values.iter() {
            total.packets += v.packets;
            total.passed += v.passed;
            total.dropped += v.dropped;
            total.blocked += v.blocked;
        }
        Ok(total)
    }

    /// 清理过期的连接跟踪条目，返回清理条数。
    pub fn prune_conntrack(&mut self, cfg: &Conntrack) -> Result<u64> {
        let mut map: HashMap<_, FiveTuple, CtValue> = HashMap::try_from(
            self.ebpf
                .map_mut("CONNTRACK")
                .context("CONNTRACK map not found")?,
        )?;
        let timeouts = cfg.timeouts();
        let now = monotonic_ns();
        let entries: Vec<(FiveTuple, CtValue)> = map.iter().filter_map(|r| r.ok()).collect();
        let mut removed = 0u64;
        let mut removed_keys: Vec<FiveTuple> = Vec::new();
        for (k, v) in entries {
            if ct_expired(&v, now, &timeouts) {
                if map.remove(&k).is_ok() {
                    removed += 1;
                    removed_keys.push(k);
                }
            }
        }
        if removed > 0 {
            info!("conntrack pruned {removed} expired entries");
        }
        drop(map);
        // 同步清理用户态 L7 元数据：被清理条目的正向/反向 key 都删除，
        // 并做一次孤儿条目 TTL 清扫（eve 事件先于 conntrack 条目到达等场景）。
        self.cleanup_session_meta(removed_keys, &timeouts, now);
        Ok(removed)
    }

    /// 删除 `session_meta` 中已失效的条目：
    /// 1. `removed_keys`（已从 CONNTRACK 删除）的正向/反向 key 直接移除；
    /// 2. 未被任何现存 CONNTRACK 条目引用、且超过最大状态超时的孤儿条目移除。
    fn cleanup_session_meta(
        &mut self,
        removed_keys: Vec<FiveTuple>,
        timeouts: &[u32; CT_STATE_MAX],
        now: u64,
    ) {
        let mut meta = self.session_meta.lock().unwrap();
        for k in removed_keys {
            meta.remove(&k);
            meta.remove(&k.reverse());
        }
        // 孤儿 TTL：取所有状态超时的最大值（若无配置则回退 1 小时）。
        let max_timeout_ns = timeouts
            .iter()
            .copied()
            .filter(|t| *t != 0)
            .max()
            .map(|s| (s as u64) * 1_000_000_000)
            .unwrap_or(3600 * 1_000_000_000u64);
        if meta.is_empty() {
            return;
        }
        let stale: Vec<FiveTuple> = meta
            .iter()
            .filter(|(_, m)| now > m.last_updated && now - m.last_updated > max_timeout_ns)
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            meta.remove(&k);
        }
    }

    /// 导出全部连接跟踪会话（`/api/v1/operational/sessions`）。
    pub fn dump_sessions(&mut self) -> Result<Vec<k_firewall_common::api::SessionOut>> {
        let map: HashMap<_, FiveTuple, CtValue> = HashMap::try_from(
            self.ebpf
                .map_mut("CONNTRACK")
                .context("CONNTRACK map not found")?,
        )?;
        let meta = self.session_meta.lock().unwrap();
        let now = monotonic_ns();
        let timeouts = self.ct_timeouts;
        // CLOCK_MONOTONIC -> Unix 秒换算：由当前两个时钟差值推算。
        let unix_secs_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mono_secs_now = now / 1_000_000_000;
        let unix_offset = unix_secs_now.saturating_sub(mono_secs_now);
        let mut out = Vec::new();
        for r in map.iter() {
            let (k, v) = r?;
            // 元数据按事件原方向存一次；正向/反向 key 都写入，读取时任一命中即可。
            let m = meta
                .get(&k)
                .or_else(|| meta.get(&k.reverse()))
                .cloned()
                .unwrap_or_default();
            let idle_ns = now.saturating_sub(v.last_seen);
            let idle_secs = idle_ns / 1_000_000_000;
            let timeout_secs = timeouts[v.state as usize] as u64;
            let expire_in_secs = if timeout_secs == 0 {
                None
            } else {
                Some(timeout_secs.saturating_sub(idle_secs))
            };
            out.push(k_firewall_common::api::SessionOut {
                session_id: session_id_full(&k),
                family: if k.family == FAMILY_IPV4 {
                    "ipv4".into()
                } else {
                    "ipv6".into()
                },
                proto: session_proto_name(k.proto),
                src_ip: ip_bytes_to_string(&k.src_ip),
                src_port: k.src_port,
                dst_ip: ip_bytes_to_string(&k.dst_ip),
                dst_port: k.dst_port,
                state: session_state_name(v.state),
                is_nat: v.is_nat != 0,
                packets: v.packets,
                pkts_orig: v.pkts_orig,
                pkts_repl: v.pkts_repl,
                bytes_orig: v.bytes_orig,
                bytes_repl: v.bytes_repl,
                last_seen_ns: v.last_seen,
                idle_secs,
                expire_in_secs,
                last_seen_unix: unix_offset + (v.last_seen / 1_000_000_000),
                app_proto: m.app_proto,
                tls_fingerprint: m.tls_fingerprint,
                tls_sni: m.tls_sni,
                http_host: m.http_host,
                http_user_agent: m.http_user_agent,
                dns_query: m.dns_query,
                app_info: m.app_info,
            });
        }
        drop(meta);
        Ok(out)
    }

    /// 按过滤器删除连接跟踪会话（`DELETE /api/v1/operational/sessions`）。
    ///
    /// 过滤器字段全部可选；空过滤器 = 清空全部。`src_ip`/`dst_ip` 支持 IPv4/IPv6 文本。
    pub fn delete_sessions(
        &mut self,
        filter: &k_firewall_common::api::SessionDeleteRequest,
    ) -> Result<usize> {
        let mut map: HashMap<_, FiveTuple, CtValue> = HashMap::try_from(
            self.ebpf
                .map_mut("CONNTRACK")
                .context("CONNTRACK map not found")?,
        )?;
        let fam: Option<bool> = match filter.family.as_deref() {
            Some("ipv6") => Some(false),
            Some("ipv4") => Some(true),
            None => None,
            _ => return Err(anyhow!("family must be ipv4|ipv6")),
        };
        let want_proto = filter
            .proto
            .as_deref()
            .map(|p| proto_name_to_u8(p).map_err(|_| anyhow!("bad proto: {p}")))
            .transpose()?;
        let want_src = filter
            .src_ip
            .as_deref()
            .map(ip_string_to_bytes)
            .transpose()?;
        let want_dst = filter
            .dst_ip
            .as_deref()
            .map(ip_string_to_bytes)
            .transpose()?;
        let src_cidr = filter
            .src_cidr
            .as_deref()
            .map(CidrMatcher::parse)
            .transpose()?;
        let dst_cidr = filter
            .dst_cidr
            .as_deref()
            .map(CidrMatcher::parse)
            .transpose()?;

        let keys: Vec<FiveTuple> = map
            .iter()
            .filter_map(|r| r.ok())
            .filter(|(k, _)| {
                let is_v4 = k.family == FAMILY_IPV4;
                if let Some(v4) = fam {
                    if is_v4 != v4 {
                        return false;
                    }
                }
                if let Some(p) = want_proto {
                    if k.proto != p {
                        return false;
                    }
                }
                if let Some(ip) = want_src {
                    if k.src_ip != ip {
                        return false;
                    }
                }
                if let Some(c) = &src_cidr {
                    if !c.matches(&k.src_ip) {
                        return false;
                    }
                }
                if let Some(ip) = want_dst {
                    if k.dst_ip != ip {
                        return false;
                    }
                }
                if let Some(c) = &dst_cidr {
                    if !c.matches(&k.dst_ip) {
                        return false;
                    }
                }
                if let Some(p) = filter.src_port {
                    if k.src_port != p {
                        return false;
                    }
                }
                if let Some(p) = filter.dst_port {
                    if k.dst_port != p {
                        return false;
                    }
                }
                true
            })
            .map(|(k, _)| k)
            .collect();
        let mut removed = 0;
        let mut removed_keys: Vec<FiveTuple> = Vec::new();
        for k in keys {
            if map.remove(&k).is_ok() {
                removed += 1;
                removed_keys.push(k);
            }
        }
        drop(map);
        // 同步清理用户态 L7 元数据（被删条目的正向/反向 key）。
        if !removed_keys.is_empty() {
            let mut meta = self.session_meta.lock().unwrap();
            for k in removed_keys {
                meta.remove(&k);
                meta.remove(&k.reverse());
            }
        }
        info!("sessions deleted via API: removed={removed}");
        Ok(removed)
    }

    /// 按 `session_id` 精确切断单个会话（`DELETE /api/v1/operational/sessions/{session_id}`）。
    ///
    /// 同时删除正向 key 与其反向 key（双向匹配，任一方向命中即移除整个会话）及 L7 元数据。
    pub fn delete_session_by_id(&mut self, session_id: &str) -> Result<usize> {
        let key = session_key_from_full_id(session_id)
            .ok_or_else(|| anyhow!("invalid session_id {session_id:?}"))?;
        let mut map: HashMap<_, FiveTuple, CtValue> = HashMap::try_from(
            self.ebpf
                .map_mut("CONNTRACK")
                .context("CONNTRACK map not found")?,
        )?;
        let mut removed = 0;
        for k in [key, key.reverse()] {
            if map.remove(&k).is_ok() {
                removed += 1;
            }
        }
        if removed > 0 {
            let mut meta = self.session_meta.lock().unwrap();
            meta.remove(&key);
            meta.remove(&key.reverse());
            info!("session deleted via API: session_id={session_id} removed={removed}");
        }
        Ok(removed)
    }

    /// 读取 Suricata 规则头预过滤状态（`GET /api/v1/suricata/prefilter/stats`）。
    pub fn read_prefilter_stats(
        &mut self,
    ) -> Result<k_firewall_common::api::SuricataPrefilterStats> {
        let config_map: Array<_, u32> = Array::try_from(
            self.ebpf
                .map_mut("CONFIG")
                .context("CONFIG map not found")?,
        )?;
        let enabled = config_map.get(&CONFIG_SURICATA_PREFILTER, 0)? != 0;
        let dst = self
            .suricata_rules_dst
            .keys()
            .filter_map(|r| r.ok())
            .count() as u64;
        let dst_any = self
            .suricata_rules_dst_any
            .keys()
            .filter_map(|r| r.ok())
            .count() as u64;
        let src = self
            .suricata_rules_src
            .keys()
            .filter_map(|r| r.ok())
            .count() as u64;
        let src_any = self
            .suricata_rules_src_any
            .keys()
            .filter_map(|r| r.ok())
            .count() as u64;
        let tuples_total = dst + dst_any + src + src_any;
        Ok(k_firewall_common::api::SuricataPrefilterStats {
            enabled,
            tuples_total,
            dst,
            dst_any,
            src,
            src_any,
        })
    }

    /// 清理过期的分片流跟踪条目，返回清理条数。
    pub fn prune_frag_track(&mut self, timeout_secs: u64) -> Result<u64> {
        let mut map: HashMap<_, FragKey, u64> = HashMap::try_from(
            self.ebpf
                .map_mut("FRAG_TRACK")
                .context("FRAG_TRACK map not found")?,
        )?;
        let now = monotonic_ns();
        let timeout_ns = timeout_secs.saturating_mul(1_000_000_000);
        let entries: Vec<(FragKey, u64)> = map.iter().filter_map(|r| r.ok()).collect();
        let mut removed = 0u64;
        for (k, last) in entries {
            if now > last && now - last > timeout_ns {
                if map.remove(&k).is_ok() {
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            info!("frag track pruned {removed} expired entries");
        }
        Ok(removed)
    }

    /// 校正每源连接数 / 半开数：从 `CONNTRACK` 实际内容重算 `CONN_COUNT` / `SYN_COUNT`。
    ///
    /// XDP 只在新流建立时递增、关闭时递减；连接因超时（UDP / ICMP / 漏收 FIN）消失时
    /// XDP 无从递减，因此由 daemon 周期性地按 `CONNTRACK` 真实条目重算覆盖，防计数漂移。
    pub fn reconcile_conn_counts(&mut self) -> Result<()> {
        // 阶段 1：读 CONNTRACK 内容到用户态（borrow 随闭包结束释放）。
        let snap: Vec<(FiveTuple, CtValue)> = {
            let ct_map: HashMap<_, FiveTuple, CtValue> = HashMap::try_from(
                self.ebpf
                    .map_mut("CONNTRACK")
                    .context("CONNTRACK map not found")?,
            )?;
            ct_map.iter().filter_map(|r| r.ok()).collect()
        };
        let mut conns: std::collections::HashMap<IpKey, u32> = std::collections::HashMap::new();
        let mut syns: std::collections::HashMap<IpKey, u32> = std::collections::HashMap::new();
        for (k, v) in snap {
            if v.is_nat == k_firewall_common::maps::CT_NAT_REPLY {
                continue;
            }
            let src = match k.family {
                k_firewall_common::maps::FAMILY_IPV4 => {
                    let a =
                        u32::from_be_bytes([k.src_ip[0], k.src_ip[1], k.src_ip[2], k.src_ip[3]]);
                    IpKey::from_ipv4(a)
                }
                _ => IpKey::from_ipv6(k.src_ip),
            };
            let e = conns.entry(src).or_insert(0);
            *e = e.saturating_add(1);
            if v.state == CT_STATE_TCP_SYN_SENT || v.state == CT_STATE_TCP_SYN_RECV {
                let se = syns.entry(src).or_insert(0);
                *se = se.saturating_add(1);
            }
        }
        // 阶段 2：覆盖写回 CONN_COUNT（先清空再写，保证被删除连接来源的计数归零）。
        {
            let mut conn_map: HashMap<_, IpKey, u32> = HashMap::try_from(
                self.ebpf
                    .map_mut("CONN_COUNT")
                    .context("CONN_COUNT map not found")?,
            )?;
            let keys: Vec<IpKey> = conn_map
                .iter()
                .filter_map(|r| r.ok())
                .map(|(k, _)| k)
                .collect();
            for k in keys {
                let _ = conn_map.remove(&k);
            }
            for (k, n) in conns {
                let _ = conn_map.insert(k, n, 0);
            }
        }
        // 阶段 3：覆盖写回 SYN_COUNT。
        {
            let mut syn_map: HashMap<_, IpKey, u32> = HashMap::try_from(
                self.ebpf
                    .map_mut("SYN_COUNT")
                    .context("SYN_COUNT map not found")?,
            )?;
            let keys: Vec<IpKey> = syn_map
                .iter()
                .filter_map(|r| r.ok())
                .map(|(k, _)| k)
                .collect();
            for k in keys {
                let _ = syn_map.remove(&k);
            }
            for (k, n) in syns {
                let _ = syn_map.insert(k, n, 0);
            }
        }
        Ok(())
    }
}

// Ipv4Addr / Ipv6Addr 组合辅助（未直接使用，保留类型约束）。
#[allow(dead_code)]
fn _assert_family(_: Ipv4Addr, _: Ipv6Addr) {}

/// 清空一个 LpmTrie（遍历现有键逐个删除）。
fn clear_lpm<K: aya::Pod, V: aya::Pod>(map: &mut LpmTrie<MapData, K, V>) {
    let keys: Vec<LpmKey<K>> = map.keys().filter_map(|r| r.ok()).collect();
    for k in keys {
        let _ = map.remove(&k);
    }
}

/// Suricata eve.sock 监听任务：解析 eve.json 事件，写入 BPF map。
///
/// - flow 事件（检测到双向流量）→ 写入 SURICATA_ALLOW_MAP
/// - ftp 事件（FTP 命令/应答，含 dynamic_port）→ 写入 ALG_EXPECT（FTP 数据连接预期）
/// - 封禁（alert + severity）由 `suricata.rs` 经 `AppState::block` 处理
///   （走 RATE/BLOCKED 统一路径，此处不重复持有 BLOCKED map）。
fn spawn_suricata_listener(
    ebpf: &mut Ebpf,
    suricata: &crate::config::Suricata,
    ftp_alg_enabled: bool,
    session_meta: Arc<std::sync::Mutex<std::collections::HashMap<FiveTuple, SessionMeta>>>,
) -> Result<()> {
    // 取走 SURICATA_ALLOW_MAP（owned），可安全移入 'static 任务。
    let mut allow_map: HashMap<MapData, FiveTuple, u8> = HashMap::try_from(
        ebpf.take_map("SURICATA_ALLOW_MAP")
            .context("SURICATA_ALLOW_MAP map not found")?,
    )?;
    // FTP 数据连接预期表：daemon 依据 Suricata ftp 事件写入（src_port=0 通配）。
    let mut alg_expect: HashMap<MapData, FiveTuple, AlgExpect> = HashMap::try_from(
        ebpf.take_map("ALG_EXPECT")
            .context("ALG_EXPECT map not found")?,
    )?;

    let eve_socket = suricata.eve_socket.clone();
    let eve_file = suricata.eve_file.clone();

    tokio::spawn(async move {
        // 优先连接 eve socket（Suricata `unix_stream` 是 server 语义：Suricata 创建
        // socket 文件，daemon 作为 client connect）；连不上则 tail eve.json 文件。
        if let Some(ref socket_path) = eve_socket {
            let mut connected = false;
            for _ in 0..5 {
                match tokio::net::UnixStream::connect(socket_path).await {
                    Ok(stream) => {
                        connected = true;
                        info!("connected to Suricata eve socket {}", socket_path.display());
                        let mut lines = tokio::io::BufReader::new(stream).lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            process_suricata_event(
                                &line,
                                &mut allow_map,
                                &mut alg_expect,
                                ftp_alg_enabled,
                                &session_meta,
                            );
                        }
                        warn!("eve socket {} closed", socket_path.display());
                        break;
                    }
                    Err(e) => debug!("connect eve socket {} failed: {e}", socket_path.display()),
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            if !connected {
                warn!(
                    "cannot connect eve socket {} , fallback to tail {}",
                    socket_path.display(),
                    eve_file
                        .as_deref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                );
                if let Some(ref file_path) = eve_file {
                    tail_eve_file(
                        file_path,
                        &mut allow_map,
                        &mut alg_expect,
                        ftp_alg_enabled,
                        &session_meta,
                    )
                    .await;
                }
            }
        } else if let Some(ref file_path) = eve_file {
            tail_eve_file(
                file_path,
                &mut allow_map,
                &mut alg_expect,
                ftp_alg_enabled,
                &session_meta,
            )
            .await;
        }
    });

    Ok(())
}

/// tail eve.json 文件：读取新增行并交给 `process_suricata_event` 处理。
async fn tail_eve_file(
    file_path: &std::path::Path,
    allow_map: &mut HashMap<MapData, FiveTuple, u8>,
    alg_expect: &mut HashMap<MapData, FiveTuple, AlgExpect>,
    ftp_alg_enabled: bool,
    session_meta: &Arc<std::sync::Mutex<std::collections::HashMap<FiveTuple, SessionMeta>>>,
) {
    let mut last_pos = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Ok(metadata) = std::fs::metadata(file_path) {
            let len = metadata.len();
            if len > last_pos {
                if let Ok(file) = std::fs::File::open(file_path) {
                    use std::io::{BufRead, Seek};
                    let mut reader = std::io::BufReader::new(file);
                    reader.seek(std::io::SeekFrom::Start(last_pos)).ok();
                    let mut line = String::new();
                    while reader.read_line(&mut line).unwrap_or(0) > 0 {
                        debug!("eve tail line: {}", &line[..line.len().min(120)]);
                        process_suricata_event(
                            &line,
                            allow_map,
                            alg_expect,
                            ftp_alg_enabled,
                            session_meta,
                        );
                        line.clear();
                    }
                }
                last_pos = len;
            } else if len < last_pos {
                last_pos = 0;
            }
        }
    }
}

/// 解析单行 Suricata eve.json 事件并更新 BPF map 与会话元数据。
fn process_suricata_event(
    line: &str,
    allow_map: &mut HashMap<MapData, FiveTuple, u8>,
    alg_expect: &mut HashMap<MapData, FiveTuple, AlgExpect>,
    ftp_alg_enabled: bool,
    session_meta: &Arc<std::sync::Mutex<std::collections::HashMap<FiveTuple, SessionMeta>>>,
) {
    let event: SuricataEvent = match serde_json::from_str(line) {
        Ok(e) => e,
        Err(_) => return,
    };

    // FTP ALG：`ftp` 事件携带数据连接动态端口 → 写入 ALG_EXPECT。
    if ftp_alg_enabled {
        if let Some(ftp) = event.ftp.as_ref() {
            process_ftp_event(&event, ftp, alg_expect);
        }
    }

    // 解析五元组（flow / tls / http / dns 事件都携带顶层 5 元组）。
    let key = match (
        &event.src_ip,
        &event.dst_ip,
        &event.proto,
        &event.src_port,
        &event.dst_port,
    ) {
        (Some(src_ip), Some(dst_ip), Some(proto), Some(src_port), Some(dst_port)) => {
            if let (Ok(s), Ok(d)) = (
                src_ip.parse::<std::net::Ipv4Addr>(),
                dst_ip.parse::<std::net::Ipv4Addr>(),
            ) {
                if let Ok(proto_num) = proto_name_to_u8(proto) {
                    // CONNTRACK 键的端口为宿主机序（eBPF `read_ports` 直接存入），
                    // 事件侧端口须保持一致才能命中同一五元组。
                    Some(FiveTuple::from_ipv4(
                        u32::from(s),
                        u32::from(d),
                        proto_num,
                        *src_port,
                        *dst_port,
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    };

    // 允许：flow 事件（双向流量已建立）。
    if event.flow.is_some() {
        debug!(
            "eve flow event: src={:?} dst={:?} sport={:?} dport={:?} proto={:?} app={:?}",
            event.src_ip,
            event.dst_ip,
            event.src_port,
            event.dst_port,
            event.proto,
            event.app_proto
        );
        if let Some(key) = &key {
            let _ = allow_map.insert(key, 1, 0);
            let _ = allow_map.insert(&key.reverse(), 1, 0);
        }
    }

    // 会话元数据：合并 app 协议 / TLS 指纹 / HTTP / DNS 到 CONNTRACK 对应的五元组。
    if let Some(key) = &key {
        let mut meta = SessionMeta::default();
        if let Some(app) = event.app_proto.as_ref() {
            if !app.eq_ignore_ascii_case("failed") {
                meta.app_proto = Some(app.to_ascii_lowercase());
            }
        }
        if let Some(t) = event.tls.as_ref() {
            meta.tls_fingerprint = t.fingerprint.clone().or_else(|| t.ja3.clone());
            meta.tls_sni = t.sni.clone();
            if let Some(v) = t.version.as_ref() {
                meta.app_info = Some(format!("TLS {v}"));
            }
        }
        if let Some(h) = event.http.as_ref() {
            meta.http_host = h.hostname.clone();
            meta.http_user_agent = h.http_user_agent.clone();
            if let Some(m) = h.http_method.as_ref() {
                let url = h.url.clone().unwrap_or_default();
                let status = h.status.map(|s| format!(" {s}")).unwrap_or_default();
                meta.app_info = Some(format!("{m} {url}{status}"));
            }
        }
        if let Some(d) = event.dns.as_ref() {
            let q = d.query.clone().or_else(|| d.rrname.clone());
            meta.dns_query = q.clone();
            if let Some(q) = q {
                let dt = d.dtype.clone().unwrap_or_else(|| "query".into());
                meta.app_info = Some(format!("{dt} {q}"));
            }
        }
        if meta.app_proto.is_some() || meta.tls_fingerprint.is_some() || meta.http_host.is_some() {
            let mut map = session_meta.lock().unwrap();
            // 事件方向的 key 与反向 key 都合并，保证 dump 时正向/反向都能命中。
            // 注意：不能用 `or_insert(meta)` 只写缺失项——反向 key 已有旧条目时
            // 不会覆盖，导致该方向新合并的字段丢失。这里对两个方向都执行字段级合并。
            for k2 in [*key, key.reverse()] {
                let entry = map.entry(k2).or_default();
                entry.last_updated = monotonic_ns();
                if let Some(v) = meta.app_proto.as_ref() {
                    entry.app_proto = Some(v.clone());
                }
                if let Some(v) = meta.tls_fingerprint.as_ref() {
                    entry.tls_fingerprint = Some(v.clone());
                }
                if let Some(v) = meta.tls_sni.as_ref() {
                    entry.tls_sni = Some(v.clone());
                }
                if let Some(v) = meta.http_host.as_ref() {
                    entry.http_host = Some(v.clone());
                }
                if let Some(v) = meta.http_user_agent.as_ref() {
                    entry.http_user_agent = Some(v.clone());
                }
                if let Some(v) = meta.dns_query.as_ref() {
                    entry.dns_query = Some(v.clone());
                }
                if let Some(v) = meta.app_info.as_ref() {
                    entry.app_info = Some(v.clone());
                }
            }
        }
    }
}
/// 将 Suricata eve 的协议名（"TCP"/"UDP"/"ICMP"/"ICMPv6"）映射为 IP 协议号。
fn proto_name_to_u8(proto: &str) -> Result<u8, ()> {
    Ok(match proto.to_ascii_uppercase().as_str() {
        "TCP" => 6,
        "UDP" => 17,
        "ICMP" => 1,
        "ICMPV6" => 58,
        "GRE" => 47,
        "SCTP" => 132,
        other => other.parse::<u8>().map_err(|_| ())?,
    })
}

/// 协议号 -> 名称（会话导出用）。
fn session_proto_name(proto: u8) -> String {
    match proto {
        1 => "icmp".into(),
        6 => "tcp".into(),
        17 => "udp".into(),
        47 => "gre".into(),
        58 => "icmpv6".into(),
        132 => "sctp".into(),
        other => format!("proto-{other}"),
    }
}

/// CT_STATE_* -> 名称（会话导出用）。
fn session_state_name(state: u8) -> String {
    match state {
        CT_STATE_TCP_SYN_SENT => "SYN_SENT".into(),
        CT_STATE_TCP_SYN_RECV => "SYN_RECV".into(),
        CT_STATE_TCP_ESTABLISHED => "ESTABLISHED".into(),
        CT_STATE_TCP_FIN_WAIT => "FIN_WAIT".into(),
        CT_STATE_TCP_TIME_WAIT => "TIME_WAIT".into(),
        CT_STATE_UDP => "UDP".into(),
        CT_STATE_ICMP => "ICMP".into(),
        CT_STATE_GENERIC => "GENERIC".into(),
        other => format!("state-{other}"),
    }
}

/// 16 字节网络序地址字节 -> 可读 IP 字符串（IPv4 前 4 字节，其余填充 0）。
fn ip_bytes_to_string(bytes: &[u8; 16]) -> String {
    if bytes[4..16].iter().all(|&b| b == 0) {
        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
    } else {
        Ipv6Addr::from(*bytes).to_string()
    }
}

/// IPv4/IPv6 文本 -> 16 字节网络序地址（IPv4 前 4 字节，其余 0；与 CONNTRACK key 一致）。
fn ip_string_to_bytes(s: &str) -> Result<[u8; 16]> {
    let ip: IpAddr = s.parse().map_err(|_| anyhow!("invalid IP {s:?}"))?;
    Ok(match ip {
        IpAddr::V4(a) => {
            let mut b = [0u8; 16];
            b[0..4].copy_from_slice(&a.octets());
            b
        }
        IpAddr::V6(a) => a.octets(),
    })
}

/// CIDR 匹配器：解析 `ip/prefix`（无前缀视为 /32 或 /128），判断 16 字节地址是否命中。
///
/// 注意：IPv4 地址存 16 字节（前 4 字节有效，其余为 0）。IPv4 前缀 < 32 时只比较
/// 前 4 字节；IPv6 前缀完整比较 16 字节。
struct CidrMatcher {
    net: [u8; 16],
    prefix: u8,
    is_v4: bool,
}

impl CidrMatcher {
    fn parse(s: &str) -> Result<Self> {
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => {
                let p: u8 = p.parse().map_err(|_| anyhow!("bad CIDR prefix in {s:?}"))?;
                (ip, p)
            }
            None => (s, 0),
        };
        let addr: IpAddr = ip.parse().map_err(|_| anyhow!("bad CIDR {s:?}"))?;
        match addr {
            IpAddr::V4(a) => {
                let mut net = [0u8; 16];
                net[0..4].copy_from_slice(&a.octets());
                let prefix = if prefix == 0 { 32 } else { prefix.min(32) };
                Ok(Self {
                    net,
                    prefix,
                    is_v4: true,
                })
            }
            IpAddr::V6(a) => {
                let prefix = if prefix == 0 { 128 } else { prefix.min(128) };
                Ok(Self {
                    net: a.octets(),
                    prefix,
                    is_v4: false,
                })
            }
        }
    }

    fn matches(&self, bytes: &[u8; 16]) -> bool {
        // IPv4 匹配只取前 4 字节；IPv6 全 16 字节。
        let n = if self.is_v4 { 4 } else { 16 };
        let full_bytes = (self.prefix / 8) as usize;
        let rem_bits = self.prefix % 8;
        if full_bytes > n {
            return false;
        }
        if bytes[..full_bytes] != self.net[..full_bytes] {
            return false;
        }
        if rem_bits != 0 {
            let mask = 0xFFu8 << (8 - rem_bits);
            if bytes[full_bytes] & mask != self.net[full_bytes] & mask {
                return false;
            }
        }
        true
    }
}

/// FTP 数据连接预期条目有效期（ns，5 分钟，与历史 eBPF 侧一致）。
const FTP_EXPECT_TTL_NS: u64 = 5 * 60 * 1_000_000_000;

/// 依据 Suricata `ftp` 事件写入 `ALG_EXPECT`：学习 FTP 数据连接预期五元组。
///
/// - 被动模式（PASV/EPSV，`mode != "active"`）：数据连接 = `client -> server:port`，
///   预期键 = `(src_ip, dst_ip, tcp, 0, dynamic_port)`。
/// - 主动模式（PORT/EPRT，`mode == "active"`）：数据连接 = `server -> client:port`，
///   预期键 = `(dst_ip, src_ip, tcp, 0, dynamic_port)`。
///
/// 键的 `src_port=0` 通配与 eBPF 数据面 `wild_key` 检查一致（数据连接源端口为临时端口）。
fn process_ftp_event(
    event: &SuricataEvent,
    ftp: &SuricataFtp,
    alg_expect: &mut HashMap<MapData, FiveTuple, AlgExpect>,
) {
    let Some(port) = ftp.dynamic_port else { return };
    if port == 0 {
        return;
    }
    let (Some(src_ip), Some(dst_ip)) = (&event.src_ip, &event.dst_ip) else {
        return;
    };
    let (Ok(s), Ok(d)) = (
        src_ip.parse::<std::net::Ipv4Addr>(),
        dst_ip.parse::<std::net::Ipv4Addr>(),
    ) else {
        return;
    };

    let cmd = ftp.command.as_deref().unwrap_or("");
    // 主动模式：Suricata 的 `mode` 为 "active"（PORT/EPRT 命令）；命令名兜底。
    let active = ftp.mode.as_deref() == Some("active")
        || cmd.eq_ignore_ascii_case("PORT")
        || cmd.eq_ignore_ascii_case("EPRT");
    let key = if active {
        // 主动：数据连接反向（server -> client:port）。
        FiveTuple::from_ipv4(u32::from(d), u32::from(s), 6, 0, port)
    } else {
        // 被动：数据连接同向（client -> server:port）。
        FiveTuple::from_ipv4(u32::from(s), u32::from(d), 6, 0, port)
    };
    let exp = AlgExpect {
        expire_ns: monotonic_ns() + FTP_EXPECT_TTL_NS,
    };
    match alg_expect.insert(&key, &exp, 0) {
        Ok(_) => info!(
            "SURICATA ftp {} expect src={} dport={} mode={}",
            cmd,
            if active { dst_ip } else { src_ip },
            port,
            if active { "active" } else { "passive" }
        ),
        Err(e) => debug!("insert ALG_EXPECT {key:?} failed: {e}"),
    }
}
