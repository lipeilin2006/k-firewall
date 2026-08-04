//! Suricata 规则：WebAPI 只收 Suricata 规则文本，用 `suricatax-rule-parser`
//! 提取 L4 头部（proto/src/dst/ports），生成 eBPF `SURICATA_RULES_*` 预过滤元组
//! （IPv4；按 src/dst 通配形态分 4 张 LPM 表；正向/反向元组 + XDP 双向视图命中）；
//! 规则全文持久化到 SQLite（规则文件仅在导入/导出时使用）。
//!
//! 预过滤语义：`suricata.prefilter` 开启时，XDP 对新建流按 `SURICATA_RULES_*` 做
//! 线速准入，未命中任一规则头部的流直接丢弃（只有需要 DPI 的流量到达 Suricata）。

use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use aya::maps::lpm_trie::Key as LpmKey;
use k_firewall_common::api::SuricataRuleOut;
use suricatax_rule_parser::scanner::{RuleScanner, RuleScanEvent};
use tracing::{info, warn};

use crate::api::AppState;

/// 单条规则展开出的预过滤元组上限（正向 + 反向合计）。
const MAX_TUPLES_PER_RULE: usize = 256;

/// 运行时一条 Suricata 规则（内存态）。
#[derive(Debug, Clone)]
pub struct SuriRule {
    pub id: u64,
    /// 原始 Suricata 规则文本。
    pub suricata_str: String,
    /// 是否启用（false = 临时关闭，不参与预过滤）。
    pub enabled: bool,
    /// 是否成功下发为 eBPF 预过滤条目。
    pub prefilter: bool,
    /// 未下发的原因（IPv6 规则 / 变量 / 取反等）。
    pub prefilter_note: Option<String>,
}

impl SuriRule {
    pub fn to_out(&self) -> SuricataRuleOut {
        SuricataRuleOut {
            id: self.id,
            suricata_str: self.suricata_str.clone(),
            enabled: self.enabled,
            prefilter: self.prefilter,
            prefilter_note: self.prefilter_note.clone(),
        }
    }

    /// 依据规则文本重新解析头部并展开预过滤元组（同步全表时调用）。
    /// 预过滤状态（`prefilter`/`prefilter_note`）在增删改时由 `expand_header` 计算，
    /// 这里只负责从文本重建元组，跳过解析错误（规则仍保留但不参与预过滤）。
    pub fn tuples(&self) -> SuriTuples {
        if !self.enabled {
            return SuriTuples::default();
        }
        match parse_rule(&self.suricata_str).and_then(|p| expand_header(&p)) {
            Ok(e) => e.tuples,
            Err(_) => SuriTuples::default(),
        }
    }
}

/// 解析后的规则头部（不解析选项语义，仅 L4 头）。
#[derive(Debug, Clone)]
pub struct ParsedRule {
    pub text: String,
    pub action: String,
    pub proto: String,
    pub src_ip: String,
    pub src_port: String,
    pub direction: String,
    pub dst_ip: String,
    pub dst_port: String,
    pub sid: Option<u32>,
}

/// 用 `suricatax-rule-parser` 扫描规则，提取头部字段与 `sid` 选项。
pub fn parse_rule(text: &str) -> Result<ParsedRule> {
    let text = text.trim();
    if text.is_empty() {
        bail!("empty rule");
    }
    let mut action = String::new();
    let mut proto = String::new();
    let mut src_ip = String::new();
    let mut src_port = String::new();
    let mut direction = String::new();
    let mut dst_ip = String::new();
    let mut dst_port = String::new();
    let mut sid: Option<u32> = None;
    for ev in RuleScanner::new(text) {
        match ev? {
            RuleScanEvent::Action(a) => action = a,
            RuleScanEvent::Protocol(p) => proto = p,
            RuleScanEvent::SourceIp(ip) => src_ip = ip,
            RuleScanEvent::SourcePort(p) => src_port = p,
            RuleScanEvent::Direction(d) => direction = d,
            RuleScanEvent::DestIp(ip) => dst_ip = ip,
            RuleScanEvent::DestPort(p) => dst_port = p,
            RuleScanEvent::Option { name, value } => {
                if name.eq_ignore_ascii_case("sid") {
                    if let Some(v) = value {
                        if let Ok(s) = v.trim().parse::<u32>() {
                            sid = Some(s);
                        }
                    }
                }
            }
            // StartOfOptions / EndOfOptions / 未来新增变体（#[non_exhaustive]）。
            _ => {}
        }
    }
    if action.is_empty() || proto.is_empty() || dst_ip.is_empty() || dst_port.is_empty() {
        bail!("incomplete rule header");
    }
    Ok(ParsedRule {
        text: text.to_string(),
        action,
        proto,
        src_ip,
        src_port,
        direction,
        dst_ip,
        dst_port,
        sid,
    })
}

/// 预过滤元组（分 4 张 LPM 表，通配位在键尾）。
///
/// BPF LPM 最长前缀匹配要求通配位在键尾，故每张表把可通配字段（dst/src CIDR、
/// sport）放尾部，受限字段（proto、dport）放前；按 src/dst 通配形态选表：
/// - `dst`（13B）：`[proto, dport, src(32), dst(CIDR), sport]`，src 精确 /32、dst 非 /0。
/// - `dst_any`（9B）：`[proto, dport, dst(CIDR), sport]`，src 通配、dst 任意。
/// - `src`（13B）：`[proto, dport, dst(32), src(CIDR), sport]`，dst 精确 /32、src 非 /0。
/// - `src_any`（9B）：`[proto, dport, src(CIDR), sport]`，dst 通配、src 任意。
#[derive(Default, Clone)]
pub struct SuriTuples {
    pub dst: Vec<LpmKey<[u8; 13]>>,
    pub dst_any: Vec<LpmKey<[u8; 9]>>,
    pub src: Vec<LpmKey<[u8; 13]>>,
    pub src_any: Vec<LpmKey<[u8; 9]>>,
}

impl SuriTuples {
    pub fn is_empty(&self) -> bool {
        self.dst.is_empty()
            && self.dst_any.is_empty()
            && self.src.is_empty()
            && self.src_any.is_empty()
    }

    pub fn len(&self) -> usize {
        self.dst.len() + self.dst_any.len() + self.src.len() + self.src_any.len()
    }
}

/// 预过滤展开结果。
pub struct Expansion {
    pub tuples: SuriTuples,
    pub note: Option<String>,
}

impl Expansion {
    fn skip(note: impl Into<String>) -> Self {
        Self { tuples: SuriTuples::default(), note: Some(note.into()) }
    }
}

/// 地址/端口展开时的分类错误：`Skip` = 规则有效但无法预过滤；`Reject` = 输入非法。
enum SpecErr {
    Skip(String),
    Reject(String),
}

/// 解析 Suricata 地址字段（`any` / IPv4 / IPv4 CIDR / `[列表]`）。
/// 返回 `(网络地址, 前缀位数)` 列表；通配 = `(0, 0)`。
fn addr_spec(spec: &str) -> Result<Vec<(u32, u32)>, SpecErr> {
    let spec = spec.trim();
    if spec.is_empty() || spec == "any" {
        return Ok(vec![(0, 0)]);
    }
    if spec.starts_with('$') {
        return Err(SpecErr::Skip(format!("address variable {spec:?}")));
    }
    if spec.starts_with('!') {
        return Err(SpecErr::Skip(format!("negated address {spec:?}")));
    }
    if spec.starts_with('[') && spec.ends_with(']') {
        let inner = &spec[1..spec.len() - 1];
        let mut out = Vec::new();
        for part in inner.split(',') {
            out.extend(addr_spec(part)?);
        }
        return Ok(out);
    }
    match parse_ipv4_cidr(spec) {
        Ok(e) => Ok(vec![e]),
        Err(_) => {
            if spec.contains(':') {
                Err(SpecErr::Skip(format!("IPv6 address {spec:?} (IPv4-only pre-filter)")))
            } else {
                Err(SpecErr::Reject(format!("unsupported address {spec:?}")))
            }
        }
    }
}

/// 解析 IPv4 或 IPv4/CIDR（前缀归一化为网络地址）。
fn parse_ipv4_cidr(s: &str) -> Result<(u32, u32)> {
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip, p.parse::<u32>().map_err(|_| anyhow!("bad prefix {p:?}"))?),
        None => (s, 32),
    };
    let ip: Ipv4Addr = ip.parse().map_err(|_| anyhow!("bad IP {ip:?}"))?;
    if prefix > 32 {
        bail!("prefix /{prefix} too long");
    }
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Ok((u32::from(ip) & mask, prefix))
}

/// 解析 Suricata 端口字段（`any` / 端口 / `[列表]` / `a:b` 范围）。
/// 返回端口列表；通配用 0 表示（端口 0 实际不可用，安全）。
fn port_spec(spec: &str) -> Result<Vec<u16>, SpecErr> {
    let spec = spec.trim();
    if spec.is_empty() || spec == "any" {
        return Ok(vec![0]);
    }
    if spec.starts_with('!') {
        return Err(SpecErr::Skip(format!("negated port {spec:?}")));
    }
    if spec.starts_with('[') && spec.ends_with(']') {
        let inner = &spec[1..spec.len() - 1];
        let mut out = Vec::new();
        for part in inner.split(',') {
            out.extend(port_spec(part)?);
        }
        return Ok(out);
    }
    if let Some((a, b)) = spec.split_once(':') {
        let lo: u16 = if a.is_empty() {
            0
        } else {
            a.parse().map_err(|_| SpecErr::Reject(format!("bad port range {spec:?}")))? 
        };
        let hi: u16 = if b.is_empty() {
            u16::MAX
        } else {
            b.parse().map_err(|_| SpecErr::Reject(format!("bad port range {spec:?}")))?
        };
        if hi < lo {
            return Err(SpecErr::Reject(format!("bad port range {spec:?}")));
        }
        let n = hi as u32 - lo as u32 + 1;
        if n > 256 {
            return Err(SpecErr::Skip(format!("port range {spec:?} too large")));
        }
        // 过滤端口 0（作为通配标记，避免误判为通配）。
        return Ok((lo..=hi).filter(|p| *p != 0).collect());
    }
    let p: u16 = spec.parse().map_err(|_| SpecErr::Reject(format!("bad port {spec:?}")))?;
    Ok(vec![p])
}

/// 协议名 -> IP 协议号（`None` = 协议通配，如 any/ip）。
fn proto_byte(s: &str) -> Option<u8> {
    match s {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmp6" | "icmpv6" => Some(58),
        "igmp" => Some(2),
        "gre" => Some(47),
        "esp" => Some(50),
        "ah" => Some(51),
        "sctp" => Some(132),
        _ => None,
    }
}

/// 把一个方向的流五元组写入 4 张预过滤表之一（按其 src/dst 通配形态选表）。
///
/// 返回是否写入了元组。约束：
/// - `dport` 必须非通配（所有表均以 proto+dport 为前缀；无端口协议用精确 0）；
/// - `sport` 精确只有在紧邻的地址字段为 /32 时才可表达（否则前缀会越过通配字节
///   溢出到后段字段，导致永不命中）——不满足则跳过该方向；
/// - src/dst 两侧同为部分 CIDR（如 /8 + /16）无法归类到任一张表，跳过。
fn push_orientation(
    out: &mut SuriTuples,
    proto: u8,
    src: u32,
    src_pfx: u32,
    sport: Option<u16>,
    dst: u32,
    dst_pfx: u32,
    dport: Option<u16>,
) -> bool {
    let Some(dp) = dport else {
        return false; // 所有表都以 dport 为前缀字段。
    };
    let sport_bits = if sport.is_some() { 16 } else { 0 };
    match (src_pfx, dst_pfx) {
        (32, p) if (1..=32).contains(&p) => {
            // DST：src 精确；sport 精确仅当 dst 也为 /32。
            if p < 32 && sport.is_some() {
                return false;
            }
            let mut data = [0u8; 13];
            data[0] = proto;
            data[1..3].copy_from_slice(&dp.to_be_bytes());
            data[3..7].copy_from_slice(&src.to_be_bytes());
            data[7..11].copy_from_slice(&dst.to_be_bytes());
            if let Some(sp) = sport {
                data[11..13].copy_from_slice(&sp.to_be_bytes());
            }
            out.dst.push(LpmKey::new(56 + p + sport_bits, data));
        }
        (0, p) if (0..=32).contains(&p) => {
            // DST_ANY：src 通配；sport 精确仅当 dst 为 /32。
            if p < 32 && sport.is_some() {
                return false;
            }
            let mut data = [0u8; 9];
            data[0] = proto;
            data[1..3].copy_from_slice(&dp.to_be_bytes());
            data[3..7].copy_from_slice(&dst.to_be_bytes());
            if let Some(sp) = sport {
                data[7..9].copy_from_slice(&sp.to_be_bytes());
            }
            out.dst_any.push(LpmKey::new(24 + p + sport_bits, data));
        }
        (p, 32) if (1..=32).contains(&p) => {
            // SRC：dst 精确；sport 精确仅当 src 为 /32（p==32 时其实走 DST 分支）。
            if p < 32 && sport.is_some() {
                return false;
            }
            let mut data = [0u8; 13];
            data[0] = proto;
            data[1..3].copy_from_slice(&dp.to_be_bytes());
            data[3..7].copy_from_slice(&dst.to_be_bytes());
            data[7..11].copy_from_slice(&src.to_be_bytes());
            if let Some(sp) = sport {
                data[11..13].copy_from_slice(&sp.to_be_bytes());
            }
            out.src.push(LpmKey::new(56 + p + sport_bits, data));
        }
        (p, 0) if (1..=32).contains(&p) => {
            // SRC_ANY：dst 通配；sport 精确仅当 src 为 /32。
            if p < 32 && sport.is_some() {
                return false;
            }
            let mut data = [0u8; 9];
            data[0] = proto;
            data[1..3].copy_from_slice(&dp.to_be_bytes());
            data[3..7].copy_from_slice(&src.to_be_bytes());
            if let Some(sp) = sport {
                data[7..9].copy_from_slice(&sp.to_be_bytes());
            }
            out.src_any.push(LpmKey::new(24 + p + sport_bits, data));
        }
        // src/dst 均为部分 CIDR（或无法归类）：不表达。
        _ => return false,
    }
    true
}

/// 把规则头部展开为 eBPF `SURICATA_RULES_*` 预过滤元组（IPv4）。
///
/// 正向与反向（src/dst、sport/dport 互换）元组都写入；XDP 对新建流同时查正向与
/// 反向视图，双向流命中同一批元组。键布局见 [`SuriTuples`]。命中任一表 = 该流
/// 需要 Suricata/DPI 检测。
pub fn expand_header(parsed: &ParsedRule) -> Result<Expansion> {
    let proto_name = parsed.proto.to_lowercase();
    if matches!(proto_name.as_str(), "ip6" | "ipv6" | "icmp6" | "icmpv6") {
        return Ok(Expansion::skip("IPv6 protocol rule"));
    }
    let proto = proto_byte(&proto_name);
    if proto.is_none() && !matches!(proto_name.as_str(), "any" | "ip" | "") {
        return Ok(Expansion::skip(format!("protocol {proto_name:?}")));
    }
    let Some(proto) = proto else {
        return Ok(Expansion::skip("protocol any/ip (needs specific protocol)"));
    };
    // 无端口协议（ICMP/GRE/ESP/AH/IGMP）：XDP `read_ports` 返回 (0,0)，把端口当作
    // 精确 0 下发，否则这类规则永远无法表达、开启预过滤后会把相关流量全部丢弃。
    let portless = matches!(proto, 1 | 2 | 47 | 50 | 51 | 58);

    macro_rules! expand_field {
        ($f:expr) => {{
            match $f {
                Ok(v) => v,
                Err(SpecErr::Skip(msg)) => return Ok(Expansion::skip(msg)),
                Err(SpecErr::Reject(msg)) => return Err(anyhow!(msg)),
            }
        }};
    }
    let srcs = expand_field!(addr_spec(&parsed.src_ip));
    let dsts = expand_field!(addr_spec(&parsed.dst_ip));
    let sports = if portless {
        vec![0]
    } else {
        expand_field!(port_spec(&parsed.src_port))
    };
    let dports = if portless {
        vec![0]
    } else {
        expand_field!(port_spec(&parsed.dst_port))
    };

    let combos = srcs.len() * dsts.len() * sports.len() * dports.len();
    // 每个组合写入正向 + 反向各一（反向依赖 dport 落在对侧，见 push_orientation）。
    if combos * 2 > MAX_TUPLES_PER_RULE {
        bail!(
            "rule expands to too many prefilter tuples ({combos}); limit {}",
            MAX_TUPLES_PER_RULE
        );
    }

    // 正向 + 反向元组都写入：XDP 对新建流同时查「正向视图」与「反向视图」（src/dst
    // 与 sport/dport 互换），四个方向全部命中同一批元组，覆盖双向流且不误判。
    //
    // 预过滤是默认拒绝语义：一旦某个组合正/反向都无法表达，未表达部分会被线速
    // 丢弃，因此整条规则放弃预过滤（交回常规检测，宁可不优化也不能误杀）。
    let mut tuples = SuriTuples::default();
    let mut all_expressible = true;
    for (src_net, src_pfx) in &srcs {
        for (dst_net, dst_pfx) in &dsts {
            for sport in &sports {
                for dport in &dports {
                    let sp = if portless { None } else if *sport == 0 { None } else { Some(*sport) };
                    let dp = if portless { Some(0) } else if *dport == 0 { None } else { Some(*dport) };
                    let fwd = push_orientation(
                        &mut tuples,
                        proto,
                        *src_net,
                        *src_pfx,
                        sp,
                        *dst_net,
                        *dst_pfx,
                        dp,
                    );
                    // 反向视图：src/dst 与 sport/dport 互换后按同一批元组匹配。
                    let rev = push_orientation(
                        &mut tuples,
                        proto,
                        *dst_net,
                        *dst_pfx,
                        dp,
                        *src_net,
                        *src_pfx,
                        sp,
                    );
                    if !fwd && !rev {
                        all_expressible = false;
                    }
                }
            }
        }
    }
    if !all_expressible {
        return Ok(Expansion::skip(
            "rule header partially inexpressible as prefilter (e.g. exact source port with \
             partial CIDR); not prefiltered to avoid silent drops",
        ));
    }
    let note = if tuples.is_empty() {
        Some(
            "rule header not expressible as prefilter (src/dst must not both be partial \
             CIDR; dport must be fixed)"
                .to_string(),
        )
    } else {
        None
    };
    Ok(Expansion { tuples, note })
}

/// 恢复持久化的 Suricata 规则到内存表并重新同步 eBPF 预过滤（启动时调用）。
pub async fn restore(state: &Arc<AppState>) -> Result<()> {
    let Some(p) = &state.persist else {
        return Ok(());
    };
    let rows = p.load_suricata_rules()?;
    let mut max_id = 0u64;
    let mut rules = Vec::with_capacity(rows.len());
    for row in rows {
        let id = row.id.unwrap_or(0) as u64;
        max_id = max_id.max(id);
        // 从规则文本重新解析头部并展开预过滤元组（仅存储文本）。
        let exp = match parse_rule(&row.text).and_then(|p| expand_header(&p)) {
            Ok(e) => e,
            Err(e) => {
                warn!("restore suricata rule {id}: prefilter expansion failed: {e:#}");
                Expansion::skip("prefilter expansion failed")
            }
        };
        rules.push(SuriRule {
            id,
            suricata_str: row.text,
            enabled: row.enabled,
            prefilter: !exp.tuples.is_empty(),
            prefilter_note: exp.note,
        });
    }
    let restored_count = rules.len();
    *state.suricata_rules.lock().unwrap() = rules;
    state
        .next_suri_rule_id
        .store(max_id + 1, std::sync::atomic::Ordering::Relaxed);
    info!("restored {restored_count} suricata rules (max id {max_id})");
    state.resync_suri_prefilter().await?;
    Ok(())
}
