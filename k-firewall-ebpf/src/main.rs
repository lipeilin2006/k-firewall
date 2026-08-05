#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::{
    bindings,
    bindings::xdp_action,
    macros::{classifier, map, xdp},
    maps::{
        Array, DevMap, HashMap, LruHashMap, PerCpuArray, RingBuf, lpm_trie::Key as LpmKey,
        lpm_trie::LpmTrie,
    },
    programs::{TcContext, XdpContext},
};
use aya_log_ebpf::info;
use core::mem;
use k_firewall_common::maps::{
    AlgExpect, CT_COUNTED_CONN, CT_COUNTED_SYN, CT_STATE_GENERIC, CT_STATE_ICMP,
    CT_STATE_TCP_ESTABLISHED, CT_STATE_TCP_FIN_WAIT, CT_STATE_TCP_SYN_RECV, CT_STATE_TCP_SYN_SENT,
    CT_STATE_TCP_TIME_WAIT, CT_STATE_UDP, ConnLimit, CtValue, DnatKey, DnatValue, FRAG_POLICY_DROP,
    FRAG_POLICY_INSPECT, FiveTuple, FragKey, IpKey, MODE_HYBRID, MODE_ROUTE, MODE_TRANSPARENT,
    QosBucket, ROLE_LAN, RateState, SESSION_BLOCKED, SESSION_DROP, SESSION_NEW, SessionEvent,
    SynState, VifConfig, VifKey,
};
use k_firewall_common::{
    ACTION_DROP, ACTION_PASS, CONFIG_DEFAULT_ACTION, CONFIG_FRAG_TIMEOUT, CONFIG_FRAGMENT_POLICY,
    CONFIG_FTP_ALG, CONFIG_QOS_COUNT, CONFIG_RA_FILTER, CONFIG_SURICATA_PREFILTER,
    CONFIG_SYN_BURST, CONFIG_SYN_MAX_HALFOPEN, CONFIG_SYN_RATE, Stats,
};
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::Icmpv6Hdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    vlan::VlanHdr,
};

/// TCP/UDP 协议号。
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
/// ICMPv6。
const IPPROTO_ICMPV6: u8 = 58;
/// IPv6 扩展头：逐跳选项 / 路由 / 分片 / 目的选项 / AH。
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_DSTOPTS: u8 = 60;
const IPPROTO_AH: u8 = 51;

/// IPv6 扩展头遍历后 L4 偏移的上界（字节）。合法包远小于此值；
/// 畸形/巨型扩展头链在此被拒绝，同时帮助 verifier 收敛值域。
const MAX_L4_OFF: usize = 128;

/// TCP 标志位。
const TCPHDR_FIN: u8 = 0x01;
const TCPHDR_SYN: u8 = 0x02;
const TCPHDR_RST: u8 = 0x04;
const TCPHDR_ACK: u8 = 0x10;

/// ICMPv6 邻发现类型（ND）。RA / Redirect 是路由注入攻击向量，可被过滤。
const ICMPV6_RS: u8 = 133;
const ICMPV6_RA: u8 = 134;
const ICMPV6_NS: u8 = 135;
const ICMPV6_NA: u8 = 136;
const ICMPV6_REDIRECT: u8 = 137;

/// 分片解析结果（`parse_l3` 输出的一部分）。
struct FragInfo {
    /// 1 = 该包是分片（IPv4 非零偏移 / MF，或 IPv6 分片头）。
    is_fragmented: u8,
    /// 1 = 该包是首片（偏移 0，携带 L4 头）。
    is_first: u8,
}

/// 源 IP 封禁表。
#[map]
static BLOCKED: HashMap<IpKey, u64> = HashMap::with_max_entries(65536, 0);

/// 本机接口 IP 集合（路由模式"目标为本机"判断用）。
#[map]
static LOCAL_IPS: HashMap<IpKey, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(1, 0);

/// 会话日志环形缓冲（新建连接 / 丢包 / 封禁）。
#[map]
static SESSION_LOG: RingBuf = RingBuf::with_byte_size(1 << 16 /* 64 KiB */, 0);

/// 源 IP 速率限制（令牌桶）：key = 源 IP。LRU 自动淘汰冷条目。
#[map]
static RATE_LIMITS: LruHashMap<IpKey, RateState> = LruHashMap::with_max_entries(65536, 0);

/// 运行配置（数组槽位见 `k_firewall_common::CONFIG_*`）。
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(10, 0);

/// (物理接口 ifindex, VLAN ID) -> VIF 配置。
#[map]
static VIF_MAP: HashMap<VifKey, VifConfig> = HashMap::with_max_entries(1024, 0);

/// 连接跟踪表：五元组 -> 连接信息（双向匹配，见 `FiveTuple::reverse`）。
///
/// NAT 回程条目（`is_nat == CT_NAT_REPLY`）也存于此：TC Egress / DNAT 注入的
/// 回程预期五元组，XDP 在正向查找命中即判定为合法 NAT 回程并放行。
#[map]
static CONNTRACK: HashMap<FiveTuple, CtValue> = HashMap::with_max_entries(65536, 0);

/// 每状态超时（秒）：槽位 = `CT_STATE_*`。daemon 启动时按配置写入。
#[map]
static CT_TIMEOUTS: Array<u32> =
    Array::with_max_entries(k_firewall_common::maps::CT_STATE_MAX as u32, 0);

/// 分片流跟踪：`(src, dst, proto)` -> 最近活跃时刻（ns）。孤儿分片检测。
#[map]
static FRAG_TRACK: HashMap<FragKey, u64> = HashMap::with_max_entries(65536, 0);

/// Suricata 允许的返回流量五元组（快速放行）。
#[map]
static SURICATA_ALLOW_MAP: HashMap<FiveTuple, u8> = HashMap::with_max_entries(65536, 0);

/// Suricata 规则头预过滤 LpmTrie（IPv4，daemon 依据 WebAPI 添加的规则头部写入）。
///
/// 4 张表按 src/dst 通配形态分工（通配位在键尾）：
/// - `SURICATA_RULES_DST`（13B）：`[proto, dport, src, dst(CIDR), sport]`，src 精确。
/// - `SURICATA_RULES_DST_ANY`（9B）：`[proto, dport, dst(CIDR), sport]`，src 通配。
/// - `SURICATA_RULES_SRC`（13B）：`[proto, dport, dst, src(CIDR), sport]`，dst 精确。
/// - `SURICATA_RULES_SRC_ANY`（9B）：`[proto, dport, src(CIDR), sport]`，dst 通配。
/// 只存规则正向/反向元组；XDP 对新建流同时查正向与反向（src/dst、sport/dport
/// 互换）视图，四个方向命中同一批元组。命中 = 该流需要 Suricata/DPI 检测。
/// `CONFIG_SURICATA_PREFILTER` 开启时，未命中的新建流被丢弃。
#[map]
static SURICATA_RULES_DST: LpmTrie<[u8; 13], u8> = LpmTrie::with_max_entries(65536, 0);

#[map]
static SURICATA_RULES_DST_ANY: LpmTrie<[u8; 9], u8> = LpmTrie::with_max_entries(65536, 0);

#[map]
static SURICATA_RULES_SRC: LpmTrie<[u8; 13], u8> = LpmTrie::with_max_entries(65536, 0);

#[map]
static SURICATA_RULES_SRC_ANY: LpmTrie<[u8; 9], u8> = LpmTrie::with_max_entries(65536, 0);

/// Zone 策略 LpmTrie：`(src 接口 ifindex, dst IP)` -> 动作。
#[map]
static ZONE: LpmTrie<[u8; 8], u8> = LpmTrie::with_max_entries(4096, 0);

/// 端口转发（DNAT）规则：`(WAN IP:端口, proto)` -> 内部服务器。
#[map]
static DNAT_RULES: HashMap<DnatKey, DnatValue> = HashMap::with_max_entries(4096, 0);

/// VIF ID -> 目标物理网卡（透明模式 bpf_redirect 用）。
#[map]
static REDIRECT_DEV: DevMap = DevMap::with_max_entries(1024, 0);

/// 每源 IP 并发连接数上限（0 = 不限）。daemon 按配置下发。
#[map]
static CONN_LIMITS: HashMap<IpKey, ConnLimit> = HashMap::with_max_entries(65536, 0);

/// 每源 IP 当前并发连接计数（XDP 新建时 +1，关闭/超时校正时 -1）。
#[map]
static CONN_COUNT: HashMap<IpKey, u32> = HashMap::with_max_entries(65536, 0);

/// 每源 IP SYN 速率令牌桶（SYN Flood 防护）。key = 源 IP。LRU 自动淘汰冷/伪造源。
#[map]
static SYN_LIMITS: LruHashMap<IpKey, SynState> = LruHashMap::with_max_entries(65536, 0);

/// 每源 IP 半开（SYN_SENT/SYN_RECV）连接计数（SYN Flood 防护）。
#[map]
static SYN_COUNT: HashMap<IpKey, u32> = HashMap::with_max_entries(65536, 0);

/// FTP 数据连接预期表：`(client_ip, server_ip, proto, dport, sport)` -> 过期时刻（ns）。
/// FTP ALG 控制流解析出 PORT/PASV 参数后写入；数据连接新建时命中即放行。
#[map]
static ALG_EXPECT: HashMap<FiveTuple, AlgExpect> = HashMap::with_max_entries(8192, 0);

/// QoS 分类配置（只读；daemon 下发，首匹配生效）。
#[map]
static QOS_CLASSES: Array<k_firewall_common::maps::QosConfig> =
    Array::with_max_entries(k_firewall_common::maps::QOS_MAX, 0);

/// QoS 每类入口限速令牌桶（per-CPU，无竞争）。
#[map]
static QOS_BUCKETS: PerCpuArray<QosBucket> =
    PerCpuArray::with_max_entries(k_firewall_common::maps::QOS_MAX, 0);

#[xdp]
pub fn k_firewall(ctx: XdpContext) -> u32 {
    match try_k_firewall(ctx) {
        Ok(ret) => ret,
        // 无法解析（如截断的短包）时放行，交由内核协议栈处理。
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data() as *const u8;
    let end = ctx.data_end() as *const u8;
    let len = mem::size_of::<T>();

    // 指针算术 + 指针比较（旧版验证过的模式）：`p + len > end`，
    // verifier 会把范围约束绑定到 p，后续读取可证明。
    let p = start.add(offset);
    if p.add(len) > end {
        return Err(());
    }

    Ok(p as *const T)
}

/// 可写指针（QoS DSCP 改写用）。
#[inline(always)]
unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    Ok(ptr_at::<T>(ctx, offset)? as *mut T)
}

#[inline(always)]
fn bump_stats(passed: bool, blocked: bool) {
    if let Some(stats) = STATS.get_ptr_mut(0) {
        let stats = unsafe { &mut *stats };
        stats.packets += 1;
        if blocked {
            stats.blocked += 1;
        }
        if passed {
            stats.passed += 1;
        } else {
            stats.dropped += 1;
        }
    }
}

/// 向 `SESSION_LOG` 写入一条会话事件（新建 / 丢包 / 封禁）。
#[inline(always)]
fn log_session(
    action: u8,
    is_ipv4: bool,
    proto: u8,
    ifindex: usize,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
) {
    let ev = if is_ipv4 {
        SessionEvent::ipv4(
            action,
            proto,
            ifindex as u32,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        )
    } else {
        return;
    };
    let _ = SESSION_LOG.output::<SessionEvent>(&ev, 0);
}

/// IPv6 版：源/目的为 16 字节。
#[inline(always)]
fn log_session_v6(
    action: u8,
    proto: u8,
    ifindex: usize,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
) {
    let ev = SessionEvent::ipv6(
        action,
        proto,
        ifindex as u32,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    );
    let _ = SESSION_LOG.output::<SessionEvent>(&ev, 0);
}

/// 速率限制令牌桶：对源 IP 扣一个令牌。桶空返回 `true`（应丢弃）。
///
/// 只在 `RATE_LIMITS` 中存在该源 IP 条目时生效；未配置限速的流量直接放行。
#[inline(always)]
fn rate_limited(is_ipv4: bool, src_ip: u32, src_ip6: [u8; 16], now: u64) -> bool {
    let key = if is_ipv4 {
        IpKey::from_ipv4(src_ip)
    } else {
        IpKey::from_ipv6(src_ip6)
    };
    let state_ptr = RATE_LIMITS.get_ptr_mut(&key);
    if state_ptr.is_none() {
        return false;
    }
    let state = unsafe { &mut *state_ptr.unwrap() };
    if now > state.last {
        let elapsed = now - state.last;
        let add = (elapsed * state.rate as u64) / 1_000_000_000;
        let add = add.min(state.burst as u64 - state.tokens as u64);
        state.tokens += add as u32;
        state.last = now;
    }
    if state.tokens == 0 {
        true
    } else {
        state.tokens -= 1;
        false
    }
}

/// 构造源 IP 键（IPv4 高 4 字节 / IPv6 全 16 字节）。
#[inline(always)]
fn src_ip_key(is_ipv4: bool, src_ip: u32, src_ip6: [u8; 16]) -> IpKey {
    if is_ipv4 {
        IpKey::from_ipv4(src_ip)
    } else {
        IpKey::from_ipv6(src_ip6)
    }
}

/// 每源 IP 并发连接数检查：超过 `CONN_LIMITS` 上限则丢弃，否则 `CONN_COUNT` +1。
///
/// 只在新建流首包（本函数返回 true 代表应丢弃）调用一次；`CONN_COUNT` 的递减由
/// 连接关闭路径（`ct_count_dec`）与 daemon 周期校正共同完成。
#[inline(always)]
fn conn_limit_check(ctx: &XdpContext, is_ipv4: bool, src_ip: u32, src_ip6: [u8; 16]) -> bool {
    let key = src_ip_key(is_ipv4, src_ip, src_ip6);
    let limit = match unsafe { CONN_LIMITS.get(&key) } {
        Some(l) => l.max_conns,
        None => return false,
    };
    if limit == 0 {
        return false;
    }
    let cur = unsafe { CONN_COUNT.get(&key) }.copied().unwrap_or(0);
    if cur >= limit {
        info!(
            ctx,
            "CONN LIMIT src={:i} count={} max={}",
            if is_ipv4 { src_ip } else { 0 },
            cur,
            limit
        );
        return true;
    }
    match CONN_COUNT.get_ptr_mut(&key) {
        Some(p) => unsafe { *p += 1 },
        None => {
            let _ = CONN_COUNT.insert(&key, &1, 0);
        }
    }
    false
}

/// 连接关闭 / 超时回收时递减每源 `CONN_COUNT`。
#[inline(always)]
fn conn_count_dec(is_ipv4: bool, src_ip: u32, src_ip6: [u8; 16]) {
    let key = src_ip_key(is_ipv4, src_ip, src_ip6);
    if let Some(p) = CONN_COUNT.get_ptr_mut(&key) {
        unsafe {
            if *p > 0 {
                *p -= 1;
            }
        }
    }
}

/// SYN Flood 防护：每源 IP 令牌桶 + 半开连接数上限。
///
/// 只对 TCP 新建（SYN 且非回程）调用。任一超限返回 `true`（丢弃）。
#[inline(always)]
fn syn_flood_check(
    ctx: &XdpContext,
    is_ipv4: bool,
    src_ip: u32,
    src_ip6: [u8; 16],
    now: u64,
) -> bool {
    let rate = CONFIG.get(CONFIG_SYN_RATE).copied().unwrap_or(0);
    let burst = CONFIG.get(CONFIG_SYN_BURST).copied().unwrap_or(0);
    let max_half = CONFIG.get(CONFIG_SYN_MAX_HALFOPEN).copied().unwrap_or(0);
    if rate == 0 && max_half == 0 {
        return false;
    }
    let key = src_ip_key(is_ipv4, src_ip, src_ip6);

    // 令牌桶：rate pps / burst 突发（先判定速率，防止被丢弃的 SYN 污染半开计数）。
    if rate > 0 {
        let burst = burst.max(1);
        match SYN_LIMITS.get_ptr_mut(&key) {
            Some(p) => {
                let state = unsafe { &mut *p };
                if now > state.last {
                    let elapsed = now - state.last;
                    let add = (elapsed * rate as u64) / 1_000_000_000;
                    let add = add.min(burst as u64 - state.tokens as u64);
                    state.tokens += add as u32;
                    state.last = now;
                }
                if state.tokens == 0 {
                    info!(
                        ctx,
                        "SYN RATE LIMIT src={:i}",
                        if is_ipv4 { src_ip } else { 0 }
                    );
                    return true;
                }
                state.tokens -= 1;
            }
            None => {
                let st = SynState {
                    last: now,
                    tokens: burst.saturating_sub(1),
                };
                let _ = SYN_LIMITS.insert(&key, &st, 0);
            }
        }
    }

    // 半开连接数上限（SYN_SENT/SYN_RECV 状态）。
    if max_half > 0 {
        let cur = unsafe { SYN_COUNT.get(&key) }.copied().unwrap_or(0);
        if cur >= max_half {
            info!(
                ctx,
                "SYN HALFOPEN LIMIT src={:i} count={} max={}",
                if is_ipv4 { src_ip } else { 0 },
                cur,
                max_half
            );
            return true;
        }
        match SYN_COUNT.get_ptr_mut(&key) {
            Some(p) => unsafe { *p += 1 },
            None => {
                let _ = SYN_COUNT.insert(&key, &1, 0);
            }
        }
    }
    false
}

/// 半开连接关闭 / 握手完成时递减每源 `SYN_COUNT`。
#[inline(always)]
fn syn_count_dec(is_ipv4: bool, src_ip: u32, src_ip6: [u8; 16]) {
    let key = src_ip_key(is_ipv4, src_ip, src_ip6);
    if let Some(p) = SYN_COUNT.get_ptr_mut(&key) {
        unsafe {
            if *p > 0 {
                *p -= 1;
            }
        }
    }
}

/// 连接状态转移时回收每源计数：
/// - 半开（SYN_SENT/SYN_RECV）离开该状态 → `SYN_COUNT` -1（握手完成或关闭）。
/// - 进入 `TIME_WAIT`（连接关闭）→ `CONN_COUNT` -1。
///
/// `ip` 参数为"正向发起方"的 IP（反向路径时调用方传 `dst_ip`）。
#[inline(always)]
fn ct_counters_tick(
    nv: &mut CtValue,
    cur: u8,
    new_state: u8,
    is_ipv4: bool,
    ip: u32,
    ip6: [u8; 16],
) {
    // NAT 回程条目不参与每源计数（该连接已在正向流创建时计过一次）。
    if nv.is_nat != k_firewall_common::maps::CT_NAT_NONE {
        return;
    }
    if new_state != cur {
        let was_half = cur == CT_STATE_TCP_SYN_SENT || cur == CT_STATE_TCP_SYN_RECV;
        let still_half = new_state == CT_STATE_TCP_SYN_SENT || new_state == CT_STATE_TCP_SYN_RECV;
        if was_half && !still_half && nv.counted & CT_COUNTED_SYN != 0 {
            syn_count_dec(is_ipv4, ip, ip6);
            nv.counted &= !CT_COUNTED_SYN;
        }
        if new_state == CT_STATE_TCP_TIME_WAIT && nv.counted & CT_COUNTED_CONN != 0 {
            conn_count_dec(is_ipv4, ip, ip6);
            nv.counted &= !CT_COUNTED_CONN;
        }
    }
}

/// 判断某条连接条目是否已超过其状态的超时（被 daemon 或本路径视为过期）。
#[inline(always)]
fn ct_expired(v: &CtValue, now: u64) -> bool {
    let timeout_secs = CT_TIMEOUTS.get(v.state as u32).copied().unwrap_or(0);
    if timeout_secs == 0 {
        // 0 = 该状态未配置超时：视为永不过期。
        return false;
    }
    let timeout_ns = (timeout_secs as u64) * 1_000_000_000;
    now > v.last_seen && now - v.last_seen > timeout_ns
}

/// FTP ALG 预期条目的学习已迁移到用户态：daemon 解析 Suricata eve `ftp` 事件
/// （`command` + `dynamic_port`，覆盖主动 PORT 与被动 PASV/227），向 `ALG_EXPECT`
/// 写入预期数据连接五元组（`src_port=0` 通配）。eBPF 不再扫描载荷。
///
/// 查询 `ALG_EXPECT` 是否命中（未过期）：匹配"预期数据连接"五元组。
#[inline(always)]
fn alg_expect_hit(flow: &FiveTuple, now: u64) -> bool {
    match unsafe { ALG_EXPECT.get(flow) } {
        Some(exp) => {
            let expired = exp.expire_ns != 0 && now > exp.expire_ns;
            if expired {
                let _ = ALG_EXPECT.remove(flow);
                false
            } else {
                true
            }
        }
        None => false,
    }
}

/// FTP ALG 预期条目的学习已迁移到用户态：daemon 解析 Suricata eve `ftp` 事件
/// （`command` + `dynamic_port`，覆盖主动 PORT 与被动 PASV/227），向 `ALG_EXPECT`
/// 写入预期数据连接五元组（`src_port=0` 通配）。eBPF 不再扫描载荷。
///
/// TCP 状态转移：按当前包标志位与方向推进状态机。
#[inline(always)]
fn ct_tcp_step(flags: u8, reply: bool, cur: u8) -> u8 {
    if flags & TCPHDR_RST != 0 {
        return CT_STATE_TCP_TIME_WAIT;
    }
    if flags & TCPHDR_SYN != 0 {
        if reply && (flags & TCPHDR_ACK != 0) {
            return CT_STATE_TCP_ESTABLISHED;
        }
        if reply {
            return CT_STATE_TCP_SYN_RECV;
        }
        return CT_STATE_TCP_SYN_SENT;
    }
    if flags & TCPHDR_ACK != 0 {
        if cur == CT_STATE_TCP_SYN_SENT || cur == CT_STATE_TCP_SYN_RECV {
            return CT_STATE_TCP_ESTABLISHED;
        }
        return cur;
    }
    if flags & TCPHDR_FIN != 0 {
        return match cur {
            CT_STATE_TCP_ESTABLISHED => CT_STATE_TCP_FIN_WAIT,
            CT_STATE_TCP_FIN_WAIT => CT_STATE_TCP_TIME_WAIT,
            _ => CT_STATE_TCP_FIN_WAIT,
        };
    }
    cur
}

/// 按协议与（TCP）标志位确定新连接初始状态。
#[inline(always)]
fn ct_initial_state(proto: u8, flags: u8, reply: bool) -> u8 {
    match proto {
        IPPROTO_TCP => {
            if flags & TCPHDR_SYN != 0 {
                if reply {
                    CT_STATE_TCP_SYN_RECV
                } else {
                    CT_STATE_TCP_SYN_SENT
                }
            } else {
                CT_STATE_TCP_ESTABLISHED
            }
        }
        IPPROTO_UDP => CT_STATE_UDP,
        IPPROTO_ICMP | IPPROTO_ICMPV6 => CT_STATE_ICMP,
        _ => CT_STATE_GENERIC,
    }
}

/// QoS：按 `QOS_CLASSES` 首匹配对包打 DSCP 并做每类入口限速。
///
/// 返回 `true` 表示超出该类速率应丢弃。
#[inline(always)]
fn apply_qos(
    ctx: &XdpContext,
    l3_off: usize,
    is_ipv4: bool,
    proto: u8,
    src_port: u16,
    dst_port: u16,
) -> bool {
    let count = CONFIG.get(CONFIG_QOS_COUNT).copied().unwrap_or(0);
    if count == 0 {
        return false;
    }
    let count = count.min(k_firewall_common::maps::QOS_MAX);
    let ingress = ctx.ingress_ifindex() as u32;
    let now = unsafe { bpf_ktime_get_ns() };
    let mut i: u32 = 0;
    while i < count {
        let cfg = match QOS_CLASSES.get(i) {
            Some(c) => *c,
            None => break,
        };
        // 匹配：字段为 0 表示通配。
        if cfg.ingress_ifindex != 0 && cfg.ingress_ifindex != ingress {
            i += 1;
            continue;
        }
        if cfg.proto != 0 && cfg.proto != proto {
            i += 1;
            continue;
        }
        // 用户态以下发网络序端口（见 ebpf_loader），此处同样用网络序比较。
        if cfg.src_port != 0 && cfg.src_port != src_port.to_be() {
            i += 1;
            continue;
        }
        if cfg.dst_port != 0 && cfg.dst_port != dst_port.to_be() {
            i += 1;
            continue;
        }
        // 命中：打 DSCP（保留 ECN）。
        if is_ipv4 {
            mark_ipv4_dscp(ctx, l3_off, cfg.dscp);
        } else {
            mark_ipv6_dscp(ctx, l3_off, cfg.dscp);
        }
        // 每类入口限速（字节令牌桶）。
        if cfg.rate_bps != 0 {
            let bucket = QOS_BUCKETS.get_ptr_mut(i);
            if let Some(bucket) = bucket {
                let bucket = unsafe { &mut *bucket };
                if now > bucket.last {
                    let elapsed = now - bucket.last;
                    let add = (elapsed as u64 * cfg.rate_bps as u64) / 1_000_000_000;
                    let add = add.min(cfg.burst_bytes as u64 - bucket.tokens as u64);
                    bucket.tokens += add as u32;
                    bucket.last = now;
                }
                let pkt_len = (ctx.data_end() - ctx.data()) as u32;
                if bucket.tokens < pkt_len {
                    return true;
                }
                bucket.tokens -= pkt_len;
            }
        }
        return false;
    }
    false
}

/// 改写 IPv4 TOS 的 DSCP 字段并增量更新头部校验和（RFC 1624）。
#[inline(always)]
fn mark_ipv4_dscp(ctx: &XdpContext, l3_off: usize, dscp: u8) {
    // 取当前 ECN，保留之。
    let tos_ptr = unsafe { ptr_at::<u8>(ctx, l3_off + 1) };
    let Ok(tos_ptr) = tos_ptr else { return };
    let old_tos = unsafe { *tos_ptr };
    let ecn = old_tos & 0x3;
    let new_tos = (dscp & 0x3F) << 2 | ecn;
    if new_tos == old_tos {
        return;
    }
    // tot_len[0] 参与 TOS 所在 16 位字，读取并保持。
    let tot_len0 = match unsafe { ptr_at::<u8>(ctx, l3_off + 2) } {
        Ok(p) => unsafe { *p },
        Err(_) => return,
    };
    // 校验和（字节 10..12）。
    let (Ok(c0), Ok(c1)) = (unsafe { ptr_at::<u8>(ctx, l3_off + 10) }, unsafe {
        ptr_at::<u8>(ctx, l3_off + 11)
    }) else {
        return;
    };
    let hc: u32 = (((unsafe { *c0 }) as u32) << 8) | (unsafe { *c1 }) as u32;
    let m_old: u32 = ((old_tos as u32) << 8) | (tot_len0 as u32);
    let m_new: u32 = ((new_tos as u32) << 8) | (tot_len0 as u32);
    // RFC 1624: HC' = ~(~HC + ~m + m')（折叠）。
    // eBPF verifier 对 while 循环状态爆炸，这里展开为固定两次折叠：
    // u32 最多两次进位后 sum < 2^16。
    let mut sum: u32 = ((!hc) & 0xFFFF) + ((!m_old) & 0xFFFF) + m_new;
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    let new_hc = !(sum as u16);
    // 回写 tos 与校验和（网络序字节）。
    let tos_mut = unsafe { ptr_at_mut::<u8>(ctx, l3_off + 1) };
    let c0_mut = unsafe { ptr_at_mut::<u8>(ctx, l3_off + 10) };
    let c1_mut = unsafe { ptr_at_mut::<u8>(ctx, l3_off + 11) };
    if let Ok(p) = tos_mut {
        unsafe { *p = new_tos };
    }
    if let (Ok(a), Ok(b)) = (c0_mut, c1_mut) {
        unsafe {
            *a = (new_hc >> 8) as u8;
            *b = new_hc as u8;
        }
    }
}

/// 改写 IPv6 Traffic Class 的 DSCP 字段（IPv6 无头部校验和，无需更新）。
#[inline(always)]
fn mark_ipv6_dscp(ctx: &XdpContext, l3_off: usize, dscp: u8) {
    let vcf0 = match unsafe { ptr_at::<u8>(ctx, l3_off) } {
        Ok(p) => unsafe { *p },
        Err(_) => return,
    };
    let vcf1 = match unsafe { ptr_at::<u8>(ctx, l3_off + 1) } {
        Ok(p) => unsafe { *p },
        Err(_) => return,
    };
    let old_dscp = ((vcf0 & 0x0F) as u32) << 2 | ((vcf1 as u32) >> 6) & 0x3;
    if (old_dscp as u8) == dscp {
        return;
    }
    let ecn = (vcf1 >> 4) & 0x3;
    let vcf0_mut = unsafe { ptr_at_mut::<u8>(ctx, l3_off) };
    let vcf1_mut = unsafe { ptr_at_mut::<u8>(ctx, l3_off + 1) };
    if let Ok(p) = vcf0_mut {
        unsafe { *p = (vcf0 & 0xF0) | ((dscp >> 2) & 0x0F) };
    }
    if let Ok(p) = vcf1_mut {
        unsafe { *p = ((dscp & 0x03) << 6) | (ecn << 4) | (vcf1 & 0x0F) };
    }
}

/// 读取 TCP/UDP 端口；非 TCP/UDP 返回 (0, 0)。
/// 一次读取 4 字节（源端口+目的端口）避免拆字段导致 verifier id 漂移。
#[inline(always)]
fn read_ports(ctx: &XdpContext, l4_off: usize, proto: u8) -> Result<(u16, u16), ()> {
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Ok((0, 0));
    }
    // `u32` value load：端口区固定 4 字节（TCP/UDP 前 4 字节布局一致）。
    // 线上字节序 src_port 在前（低 2 字节）、dst_port 在后（高 2 字节）。
    let ports: u32 = unsafe { *ptr_at(ctx, l4_off)? };
    let src_port = u16::from_be(ports as u16);
    let dst_port = u16::from_be((ports >> 16) as u16);
    Ok((src_port, dst_port))
}

/// 更新 `FRAG_TRACK` 分片流活跃时刻（供孤儿分片放行判断）。
#[inline(always)]
fn frag_track_update(
    is_ipv4: bool,
    src_ip: u32,
    src_ip6: [u8; 16],
    dst_ip: u32,
    dst_ip6: [u8; 16],
    proto: u8,
    now: u64,
) {
    let key = if is_ipv4 {
        FragKey::from_ipv4(src_ip, dst_ip, proto)
    } else {
        FragKey::from_ipv6(src_ip6, dst_ip6, proto)
    };
    let _ = FRAG_TRACK.insert(&key, &now, 0);
}

/// 查询分片流是否已知（未过期）。
#[inline(always)]
fn frag_track_known(
    is_ipv4: bool,
    src_ip: u32,
    src_ip6: [u8; 16],
    dst_ip: u32,
    dst_ip6: [u8; 16],
    proto: u8,
    now: u64,
) -> bool {
    let key = if is_ipv4 {
        FragKey::from_ipv4(src_ip, dst_ip, proto)
    } else {
        FragKey::from_ipv6(src_ip6, dst_ip6, proto)
    };
    match unsafe { FRAG_TRACK.get(&key) } {
        Some(last) => {
            let timeout = CONFIG.get(CONFIG_FRAG_TIMEOUT).copied().unwrap_or(60) as u64;
            let timeout_ns = timeout * 1_000_000_000;
            now <= *last || now - *last <= timeout_ns
        }
        None => false,
    }
}

/// 分片策略处理。返回：
/// - `Some(XDP 动作)`：本包已被策略终决（放行 / 丢弃）；
/// - `None`：继续常规检测（首片或未分片）。
#[inline(always)]
fn handle_fragments(
    ctx: &XdpContext,
    frag: &FragInfo,
    is_ipv4: bool,
    src_ip: u32,
    src_ip6: [u8; 16],
    dst_ip: u32,
    dst_ip6: [u8; 16],
    proto: u8,
) -> Option<u32> {
    if frag.is_fragmented == 0 {
        return None;
    }
    let policy = CONFIG.get(CONFIG_FRAGMENT_POLICY).copied().unwrap_or(0) as u8;
    match policy {
        FRAG_POLICY_DROP => {
            bump_stats(false, false);
            info!(&ctx, "FRAG DROP policy=drop");
            Some(xdp_action::XDP_DROP)
        }
        FRAG_POLICY_INSPECT => {
            if frag.is_first != 0 {
                // 首片：交给常规检测，放行后在插入处记录 FRAG_TRACK。
                None
            } else {
                // 非首片：必须存在已放行分片流，否则丢弃（孤儿分片）。
                let now = unsafe { bpf_ktime_get_ns() };
                if frag_track_known(is_ipv4, src_ip, src_ip6, dst_ip, dst_ip6, proto, now) {
                    bump_stats(true, false);
                    Some(xdp_action::XDP_PASS)
                } else {
                    bump_stats(false, false);
                    info!(&ctx, "FRAG DROP orphan fragment proto={}", proto);
                    Some(xdp_action::XDP_DROP)
                }
            }
        }
        _ => {
            // pass：交给内核重组（绕开 XDP 检测）。
            bump_stats(true, false);
            Some(xdp_action::XDP_PASS)
        }
    }
}

/// Suricata 规则头预过滤查表：对给定流五元组依次查 4 张 `SURICATA_RULES_*`。
/// 返回是否命中（= 该流需要 Suricata/DPI 检测）。
#[inline(always)]
fn suri_rules_hit(proto: u8, src_ip: u32, dst_ip: u32, sport: u16, dport: u16) -> bool {
    // DST 布局：proto, dport, src, dst, sport（src 精确）。
    let mut data = [0u8; 13];
    data[0] = proto;
    data[1..3].copy_from_slice(&dport.to_be_bytes());
    data[3..7].copy_from_slice(&src_ip.to_be_bytes());
    data[7..11].copy_from_slice(&dst_ip.to_be_bytes());
    data[11..13].copy_from_slice(&sport.to_be_bytes());
    if SURICATA_RULES_DST.get(&LpmKey::new(104, data)).is_some() {
        return true;
    }
    // DST_ANY 布局：proto, dport, dst, sport（src 通配）。
    let mut data = [0u8; 9];
    data[0] = proto;
    data[1..3].copy_from_slice(&dport.to_be_bytes());
    data[3..7].copy_from_slice(&dst_ip.to_be_bytes());
    data[7..9].copy_from_slice(&sport.to_be_bytes());
    if SURICATA_RULES_DST_ANY.get(&LpmKey::new(72, data)).is_some() {
        return true;
    }
    // SRC 布局：proto, dport, dst, src, sport（dst 精确）。
    let mut data = [0u8; 13];
    data[0] = proto;
    data[1..3].copy_from_slice(&dport.to_be_bytes());
    data[3..7].copy_from_slice(&dst_ip.to_be_bytes());
    data[7..11].copy_from_slice(&src_ip.to_be_bytes());
    data[11..13].copy_from_slice(&sport.to_be_bytes());
    if SURICATA_RULES_SRC.get(&LpmKey::new(104, data)).is_some() {
        return true;
    }
    // SRC_ANY 布局：proto, dport, src, sport（dst 通配）。
    let mut data = [0u8; 9];
    data[0] = proto;
    data[1..3].copy_from_slice(&dport.to_be_bytes());
    data[3..7].copy_from_slice(&src_ip.to_be_bytes());
    data[7..9].copy_from_slice(&sport.to_be_bytes());
    SURICATA_RULES_SRC_ANY.get(&LpmKey::new(72, data)).is_some()
}

fn try_k_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    // 解析 VLAN（802.1Q / 802.1ad）。
    let mut vlan_id: u16 = 0;
    let mut l3_off = EthHdr::LEN;
    let mut ether_type = unsafe { (*ethhdr).ether_type };
    if ether_type == EtherType::Ieee8021q as u16 || ether_type == EtherType::Ieee8021ad as u16 {
        let vlan: *const VlanHdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
        vlan_id = unsafe { (*vlan).vid() };
        ether_type = unsafe { (*vlan).ether_type };
        l3_off += VlanHdr::LEN;
    }

    let is_ipv4 = ether_type == EtherType::Ipv4 as u16;
    let is_ipv6 = ether_type == EtherType::Ipv6 as u16;

    // VIF 入口统一映射。
    let vif_key = VifKey {
        phy_ifindex: ctx.ingress_ifindex() as u32,
        vlan_id,
        _pad: 0,
    };
    let vif = match unsafe { VIF_MAP.get(&vif_key) } {
        Some(v) => *v,
        None => {
            bump_stats(true, false);
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // 非 IP 帧（ARP 等）：不检测，交给内核 / bridge。
    if !is_ipv4 && !is_ipv6 {
        bump_stats(true, false);
        return Ok(xdp_action::XDP_PASS);
    }

    // ---- 协议族专用解析：地址 / 协议 / 端口 / 分片信息 ----
    let (src_ip, dst_ip, proto, l4_off, src_port, dst_port, frag) = if is_ipv4 {
        let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, l3_off)? };
        let src_addr = unsafe { (*ipv4hdr).src_addr };
        let dst_addr = unsafe { (*ipv4hdr).dst_addr };
        let proto = unsafe { (*ipv4hdr).proto };
        let iphdr_len = (((unsafe { (*ipv4hdr).vihl }) & 0x0F) as usize) * 4;
        let (sp, dp) = read_ports(&ctx, l3_off + iphdr_len, proto)?;
        // 分片：MF 标志（frag_flags & 0x1）或非零偏移。
        let frag_flags = unsafe { (*ipv4hdr).frag_flags() };
        let frag_offset = unsafe { (*ipv4hdr).frag_offset() };
        let is_fragmented = if frag_offset != 0 || (frag_flags & 0x1) != 0 {
            1
        } else {
            0
        };
        let is_first = if frag_offset == 0 && (frag_flags & 0x1) != 0 {
            1
        } else {
            0
        };
        (
            u32::from_be_bytes(src_addr),
            u32::from_be_bytes(dst_addr),
            proto,
            l3_off + iphdr_len,
            sp,
            dp,
            FragInfo {
                is_fragmented,
                is_first,
            },
        )
    } else {
        let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, l3_off)? };
        let src_addr = unsafe { (*ipv6hdr).src_addr };
        let dst_addr = unsafe { (*ipv6hdr).dst_addr };
        let mut proto = unsafe { (*ipv6hdr).next_hdr };
        let mut l4_off = l3_off + Ipv6Hdr::LEN;
        let mut is_fragmented: u8 = 0;
        let mut is_first: u8 = 0;
        // 有界遍历扩展头（跳变式长度字段），最多 8 个。
        let mut remaining = 5;
        loop {
            match proto {
                IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                    if remaining == 0 {
                        return Err(());
                    }
                    remaining -= 1;
                    let hdr: *const [u8; 2] = unsafe { ptr_at(&ctx, l4_off)? };
                    let next = unsafe { (*hdr)[0] };
                    let ext_len = unsafe { (*hdr)[1] };
                    proto = next;
                    l4_off += ((ext_len as usize) + 1) * 8;
                    // 钳制扩展头长度：畸形包返回 Err，避免 verifier 值域膨胀。
                    if l4_off > MAX_L4_OFF {
                        return Err(());
                    }
                }
                IPPROTO_FRAGMENT => {
                    if remaining == 0 {
                        return Err(());
                    }
                    remaining -= 1;
                    let next = unsafe { *ptr_at::<u8>(&ctx, l4_off)? };
                    // 分片头：byte2-3 = 16 位字段（高 13 位偏移，bit0 = M）。
                    let f0 = unsafe { *ptr_at::<u8>(&ctx, l4_off + 2)? };
                    let f1 = unsafe { *ptr_at::<u8>(&ctx, l4_off + 3)? };
                    let frag_field: u16 = ((f0 as u16) << 8) | (f1 as u16);
                    let offset = frag_field >> 3;
                    let _m = frag_field & 0x1;
                    proto = next;
                    l4_off += 8;
                    if l4_off > MAX_L4_OFF {
                        return Err(());
                    }
                    is_fragmented = 1;
                    // 首片 = 偏移 0（携带 L4 头起始）。
                    if offset == 0 {
                        is_first = 1;
                    }
                }
                IPPROTO_AH => {
                    if remaining == 0 {
                        return Err(());
                    }
                    remaining -= 1;
                    let hdr: *const [u8; 2] = unsafe { ptr_at(&ctx, l4_off)? };
                    let next = unsafe { (*hdr)[0] };
                    let payload_len = unsafe { (*hdr)[1] };
                    proto = next;
                    l4_off += ((payload_len as usize) + 2) * 4;
                    if l4_off > MAX_L4_OFF {
                        return Err(());
                    }
                }
                _ => break,
            }
        }
        let (sp, dp) = read_ports(&ctx, l4_off, proto)?;
        (
            u32::from_be_bytes([src_addr[0], src_addr[1], src_addr[2], src_addr[3]]),
            u32::from_be_bytes([dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]]),
            proto,
            l4_off,
            sp,
            dp,
            FragInfo {
                is_fragmented,
                is_first,
            },
        )
    };

    let src_ip6: [u8; 16] = if is_ipv4 {
        [0; 16]
    } else {
        unsafe { *ptr_at::<Ipv6Hdr>(&ctx, l3_off)? }.src_addr
    };
    let dst_ip6: [u8; 16] = if is_ipv4 {
        [0; 16]
    } else {
        unsafe { *ptr_at::<Ipv6Hdr>(&ctx, l3_off)? }.dst_addr
    };

    // 快速路径：封禁源 IP 表。
    if is_ipv4 {
        let block_key = IpKey::from_ipv4(src_ip);
        if unsafe { BLOCKED.get(&block_key).is_some() } {
            bump_stats(false, true);
            info!(&ctx, "BLOCKED family=4 src={:i}", src_ip);
            log_session(
                SESSION_BLOCKED,
                true,
                proto,
                ctx.ingress_ifindex(),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            );
            return Ok(xdp_action::XDP_DROP);
        }
    } else {
        let block_key = IpKey::from_ipv6(src_ip6);
        if unsafe { BLOCKED.get(&block_key).is_some() } {
            bump_stats(false, true);
            info!(&ctx, "BLOCKED family=6 src={:i}", src_ip6);
            log_session_v6(
                SESSION_BLOCKED,
                proto,
                ctx.ingress_ifindex(),
                src_ip6,
                dst_ip6,
                src_port,
                dst_port,
            );
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // 分片策略。
    if let Some(ret) = handle_fragments(
        &ctx, &frag, is_ipv4, src_ip, src_ip6, dst_ip, dst_ip6, proto,
    ) {
        return Ok(ret);
    }

    // ICMPv6 ND 过滤：LAN 接口丢弃 RA / Redirect（路由注入防护）。
    if is_ipv6
        && proto == IPPROTO_ICMPV6
        && vif.role == ROLE_LAN
        && CONFIG.get(CONFIG_RA_FILTER).copied().unwrap_or(0) != 0
    {
        let icmp6: Icmpv6Hdr = unsafe { *ptr_at(&ctx, l4_off)? };
        let icmp6_type = icmp6.type_;
        if icmp6_type == ICMPV6_RA || icmp6_type == ICMPV6_REDIRECT {
            bump_stats(false, false);
            info!(&ctx, "ND FILTER icmp6_type={}", icmp6_type);
            log_session_v6(
                SESSION_DROP,
                proto,
                ctx.ingress_ifindex(),
                src_ip6,
                dst_ip6,
                src_port,
                dst_port,
            );
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Suricata 允许列表：双向匹配快速放行。
    let flow_key = if is_ipv4 {
        FiveTuple::from_ipv4(src_ip, dst_ip, proto, src_port, dst_port)
    } else {
        FiveTuple::from_ipv6(src_ip6, dst_ip6, proto, src_port, dst_port)
    };
    let rev_key = flow_key.reverse();
    if unsafe { SURICATA_ALLOW_MAP.get(&flow_key).is_some() } {
        bump_stats(true, false);
        return Ok(xdp_action::XDP_PASS);
    }
    if unsafe { SURICATA_ALLOW_MAP.get(&rev_key).is_some() } {
        bump_stats(true, false);
        return Ok(xdp_action::XDP_PASS);
    }

    // 目标为本机接口 IP：交给内核（管理流量 / NAT 回程 un-NAT）。
    let local_hit = if is_ipv4 {
        let key = IpKey::from_ipv4(dst_ip);
        unsafe { LOCAL_IPS.get(&key).is_some() }
    } else {
        let key = IpKey::from_ipv6(dst_ip6);
        unsafe { LOCAL_IPS.get(&key).is_some() }
    };
    if local_hit {
        bump_stats(true, false);
        return Ok(xdp_action::XDP_PASS);
    }

    // per-source-IP 速率限制。
    let now = unsafe { bpf_ktime_get_ns() };
    if rate_limited(is_ipv4, src_ip, src_ip6, now) {
        bump_stats(false, false);
        info!(
            &ctx,
            "RATE LIMIT family={} src={:i}",
            if is_ipv4 { 4 } else { 6 },
            src_ip
        );
        return Ok(xdp_action::XDP_DROP);
    }

    // QoS：DSCP 标记 + 每类入口限速（放行路径上所有包，含已建连接）。
    if apply_qos(&ctx, l3_off, is_ipv4, proto, src_port, dst_port) {
        bump_stats(false, false);
        info!(
            &ctx,
            "QOS LIMIT family={} proto={} dport={}",
            if is_ipv4 { 4 } else { 6 },
            proto,
            dst_port
        );
        return Ok(xdp_action::XDP_DROP);
    }

    // 连接跟踪状态机（双向匹配 + 完整 TCP 状态）。
    // 直接复用 flow_key / rev_key（后者已在应用策略处构造），避免栈上再复制两份五元组。

    // 同向命中：NAT 回程条目 / 已跟踪连接后续包。
    if let Some(v) = unsafe { CONNTRACK.get(&flow_key) } {
        if !ct_expired(&v, now) {
            let cur = v.state;
            let new_state = if proto == IPPROTO_TCP {
                // 读 TCP 标志位推进状态机。
                let flags = match unsafe { ptr_at::<u8>(&ctx, l4_off + 13) } {
                    Ok(p) => unsafe { *p },
                    Err(_) => 0,
                };
                ct_tcp_step(flags, false, cur)
            } else {
                cur
            };
            let mut nv = *v;
            nv.state = new_state;
            nv.last_seen = now;
            nv.packets = v.packets.saturating_add(1);
            nv.pkts_orig = v.pkts_orig.saturating_add(1);
            nv.bytes_orig = v
                .bytes_orig
                .saturating_add((ctx.data_end() - ctx.data()) as u64);
            // P0：半开握手完成 / 连接关闭时回收每源计数。
            ct_counters_tick(&mut nv, cur, new_state, is_ipv4, src_ip, src_ip6);
            if frag.is_fragmented != 0 {
                nv.has_fragments = 1;
                frag_track_update(is_ipv4, src_ip, src_ip6, dst_ip, dst_ip6, proto, now);
            }
            let _ = CONNTRACK.insert(&flow_key, &nv, 0);
            bump_stats(true, false);
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // 反向命中：返回包，提升正向条目状态并快速放行。
    if let Some(v) = unsafe { CONNTRACK.get(&rev_key) } {
        if !ct_expired(&v, now) {
            let new_state = if proto == IPPROTO_TCP {
                let flags = match unsafe { ptr_at::<u8>(&ctx, l4_off + 13) } {
                    Ok(p) => unsafe { *p },
                    Err(_) => 0,
                };
                ct_tcp_step(flags, true, v.state)
            } else {
                v.state
            };
            let mut nv = *v;
            nv.state = new_state;
            nv.last_seen = now;
            nv.packets = v.packets.saturating_add(1);
            nv.pkts_repl = v.pkts_repl.saturating_add(1);
            nv.bytes_repl = v
                .bytes_repl
                .saturating_add((ctx.data_end() - ctx.data()) as u64);
            // P0：半开握手完成 / 连接关闭时回收每源计数（反向路径用 dst 即正向 src）。
            ct_counters_tick(&mut nv, v.state, new_state, is_ipv4, dst_ip, dst_ip6);
            if frag.is_fragmented != 0 {
                nv.has_fragments = 1;
                frag_track_update(is_ipv4, src_ip, src_ip6, dst_ip, dst_ip6, proto, now);
            }
            let _ = CONNTRACK.insert(&rev_key, &nv, 0);
            info!(
                &ctx,
                "CT family={} proto={} sport={} dport={} state={} (reply)",
                if is_ipv4 { 4 } else { 6 },
                proto,
                src_port,
                dst_port,
                new_state
            );
            bump_stats(true, false);
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // 端口转发（DNAT）：WAN 口 ingress 命中 DNAT_RULES，注入回程 key 并放行
    // （实际改写由内核 nftables prerouting 完成）。
    if is_ipv4 {
        // DnatKey 用户态以网络序写入（见 ebpf_loader），此处同样用网络序匹配。
        let dnat_key = DnatKey::from_ipv4(dst_ip, dst_port.to_be(), proto);
        if let Some(dnat) = unsafe { DNAT_RULES.get(&dnat_key) } {
            let to_ip =
                u32::from_be_bytes([dnat.to_ip[0], dnat.to_ip[1], dnat.to_ip[2], dnat.to_ip[3]]);
            let to_port = u16::from_be(dnat.to_port);
            let reply_key = FiveTuple::from_ipv4(to_ip, src_ip, proto, to_port, src_port);
            let mut rv = CtValue::nat_reply();
            rv.last_seen = now;
            if CONNTRACK.insert(&reply_key, &rv, 0).is_ok() {
                info!(
                    &ctx,
                    "DNAT dport={} to={:i}:{} reply_to={:i}", dst_port, to_ip, to_port, src_ip
                );
            }
            bump_stats(true, false);
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // FTP ALG：数据连接命中 ALG_EXPECT（含 src_port=0 通配）即视为预期流量。
    // 预期条目由用户态 daemon 依据 Suricata eve `ftp` 事件写入；此检查放在
    // Zone/Rules 之前，确保默认 deny 下预期数据连接仍可放行。
    if CONFIG.get(CONFIG_FTP_ALG).copied().unwrap_or(0) != 0 && proto == IPPROTO_TCP && is_ipv4 {
        let wild_key = FiveTuple::from_ipv4(src_ip, dst_ip, proto, 0, dst_port);
        if alg_expect_hit(&flow_key, now) || alg_expect_hit(&wild_key, now) {
            let _ = ALG_EXPECT.remove(&flow_key);
            let _ = ALG_EXPECT.remove(&wild_key);
            // 与放行路径一致：为数据连接插入 conntrack 条目，使 SYN 重传、
            // SYN-ACK 回程与后续数据包都能走 conntrack 快速路径（否则重传即被默认 deny 丢弃）。
            let initial = ct_initial_state(
                proto,
                {
                    match unsafe { ptr_at::<u8>(&ctx, l4_off + 13) } {
                        Ok(p) => unsafe { *p },
                        Err(_) => 0,
                    }
                },
                false,
            );
            let mut nv = CtValue::new(initial);
            nv.last_seen = now;
            nv.pkts_orig = 1;
            nv.bytes_orig = (ctx.data_end() - ctx.data()) as u64;
            if CONNTRACK.insert(&flow_key, &nv, 0).is_ok() {
                info!(
                    &ctx,
                    "CT NEW (alg) family={} proto={} sport={} dport={} state={}",
                    4,
                    proto,
                    src_port,
                    dst_port,
                    initial
                );
            }
            bump_stats(true, false);
            info!(
                &ctx,
                "FTP ALG PASS family={} sport={} dport={}", 4, src_port, dst_port
            );
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // Suricata 规则头预过滤：只放行命中任一 Suricata 规则 L4 头的新建流。
    // 开启后未命中（不需要 DPI）的流在此被线速丢弃。仅对 IPv4 生效
    // （SURICATA_RULES_* 表为 IPv4 布局）；IPv6 不受影响，继续常规检测。
    if is_ipv4 && CONFIG.get(CONFIG_SURICATA_PREFILTER).copied().unwrap_or(0) != 0 {
        // 正向视图 + 反向视图（src/dst 与 sport/dport 互换）各查 4 张表。
        // 规则只存正向元组，回复方向的新连接由反向视图命中同一批元组。
        let mut pass = suri_rules_hit(proto, src_ip, dst_ip, src_port, dst_port);
        if !pass {
            pass = suri_rules_hit(proto, dst_ip, src_ip, dst_port, src_port);
        }
        if !pass {
            bump_stats(false, false);
            info!(
                &ctx,
                "SURICATA PREFILTER DROP family=4 proto={} sport={} dport={}",
                proto,
                src_port,
                dst_port
            );
            log_session(
                SESSION_DROP,
                true,
                proto,
                ctx.ingress_ifindex(),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            );
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // Zone 策略（接口级粗粒度）。
    let zone_action = {
        if is_ipv4 {
            let mut data = [0u8; 8];
            data[0..4].copy_from_slice(&(ctx.ingress_ifindex() as u32).to_be_bytes());
            data[4..8].copy_from_slice(&dst_ip.to_be_bytes());
            ZONE.get(&LpmKey::new(64, data)).copied()
        } else {
            None
        }
    };
    match zone_action {
        Some(k_firewall_common::ACTION_DROP) => {
            bump_stats(false, false);
            info!(
                &ctx,
                "ZONE DROP src_if={} dst={:i}",
                ctx.ingress_ifindex(),
                dst_ip
            );
            log_session(
                SESSION_DROP,
                true,
                proto,
                ctx.ingress_ifindex(),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            );
            return Ok(xdp_action::XDP_DROP);
        }
        Some(k_firewall_common::ACTION_PASS) => {
            bump_stats(true, false);
            return Ok(xdp_action::XDP_PASS);
        }
        _ => {}
    }

    // 默认动作：所有流量统一走默认动作（由 `CONFIG_DEFAULT_ACTION` 控制）。
    // 规则引擎已整体迁移到用户态 Suricata DPI；eBPF 仅负责预过滤与默认动作。
    let action = (CONFIG
        .get(CONFIG_DEFAULT_ACTION)
        .copied()
        .unwrap_or(ACTION_PASS as u32)) as u8;

    if action == ACTION_DROP {
        bump_stats(false, false);
        if is_ipv4 {
            info!(
                &ctx,
                "DROP family=4 src={:i} dst={:i} proto={} sport={} dport={}",
                src_ip,
                dst_ip,
                proto,
                src_port,
                dst_port
            );
            log_session(
                SESSION_DROP,
                true,
                proto,
                ctx.ingress_ifindex(),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            );
        } else {
            info!(
                &ctx,
                "DROP family=6 src={:i} dst={:i} proto={} sport={} dport={}",
                src_ip6,
                dst_ip6,
                proto,
                src_port,
                dst_port
            );
            log_session_v6(
                SESSION_DROP,
                proto,
                ctx.ingress_ifindex(),
                src_ip6,
                dst_ip6,
                src_port,
                dst_port,
            );
        }
        return Ok(xdp_action::XDP_DROP);
    }

    // 新建流首包：记录连接（初始状态由协议/标志位决定），并登记分片流。
    let initial = ct_initial_state(
        proto,
        {
            if proto == IPPROTO_TCP {
                match unsafe { ptr_at::<u8>(&ctx, l4_off + 13) } {
                    Ok(p) => unsafe { *p },
                    Err(_) => 0,
                }
            } else {
                0
            }
        },
        false,
    );

    // P0：SYN Flood 防护（仅对 TCP 新建 SYN；通过则计入半开数）。
    let tcp_syn = proto == IPPROTO_TCP && initial == CT_STATE_TCP_SYN_SENT;
    if tcp_syn && syn_flood_check(&ctx, is_ipv4, src_ip, src_ip6, now) {
        bump_stats(false, false);
        info!(
            &ctx,
            "SYN FLOOD DROP family={} src={:i} sport={} dport={}",
            if is_ipv4 { 4 } else { 6 },
            src_ip,
            src_port,
            dst_port
        );
        return Ok(xdp_action::XDP_DROP);
    }

    // P0：每源并发连接数上限（新建流计数）。
    if conn_limit_check(&ctx, is_ipv4, src_ip, src_ip6) {
        bump_stats(false, false);
        info!(
            &ctx,
            "CONN LIMIT DROP family={} src={:i} proto={}",
            if is_ipv4 { 4 } else { 6 },
            src_ip,
            proto
        );
        return Ok(xdp_action::XDP_DROP);
    }

    let mut nv = CtValue::new(initial);
    nv.last_seen = now;
    nv.pkts_orig = 1;
    nv.bytes_orig = (ctx.data_end() - ctx.data()) as u64;
    if tcp_syn {
        nv.counted |= CT_COUNTED_SYN;
    }
    nv.counted |= CT_COUNTED_CONN;
    if frag.is_fragmented != 0 {
        nv.has_fragments = 1;
        frag_track_update(is_ipv4, src_ip, src_ip6, dst_ip, dst_ip6, proto, now);
    }
    if CONNTRACK.insert(&flow_key, &nv, 0).is_ok() {
        info!(
            &ctx,
            "CT NEW family={} proto={} sport={} dport={} state={}",
            if is_ipv4 { 4 } else { 6 },
            proto,
            src_port,
            dst_port,
            initial
        );
        if is_ipv4 {
            log_session(
                SESSION_NEW,
                true,
                proto,
                ctx.ingress_ifindex(),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
            );
        } else {
            log_session_v6(
                SESSION_NEW,
                proto,
                ctx.ingress_ifindex(),
                src_ip6,
                dst_ip6,
                src_port,
                dst_port,
            );
        }
    }

    match vif.mode {
        MODE_TRANSPARENT | MODE_HYBRID | MODE_ROUTE => {
            bump_stats(true, false);
            Ok(xdp_action::XDP_PASS)
        }
        _ => {
            bump_stats(true, false);
            Ok(xdp_action::XDP_PASS)
        }
    }
}

/// TC Egress 学习程序：WAN 口出站包在 POSTROUTING（masquerade）之后执行。
///
/// 此时看到 NAT 改写后的五元组 `(WAN_IP:临时端口 -> 外网IP:端口)`，翻转成回程
/// 预期五元组 `(外网IP:端口 -> WAN_IP:临时端口)` 写入 `CONNTRACK`（`is_nat`），
/// 供 XDP Ingress 对回程包做 NAT 感知放行。
///
/// 用 `bpf_skb_load_bytes` 逐字段安全读取（TC skb 可能非线性）。
#[classifier]
pub fn kfw_tc_egress(ctx: TcContext) -> i32 {
    let eth_type_raw: u16 = match ctx.load(EthHdr::LEN - 2) {
        Ok(v) => v,
        Err(_) => return bindings::TC_ACT_OK,
    };
    let mut ether_type = eth_type_raw;
    let mut l3_off = EthHdr::LEN;
    if ether_type == EtherType::Ieee8021q as u16 || ether_type == EtherType::Ieee8021ad as u16 {
        let inner: u16 = match ctx.load(l3_off + 2) {
            Ok(v) => v,
            Err(_) => return bindings::TC_ACT_OK,
        };
        ether_type = inner;
        l3_off += VlanHdr::LEN;
    }

    if ether_type == EtherType::Ipv4 as u16 {
        let vihl: u8 = match ctx.load(l3_off) {
            Ok(v) => v,
            Err(_) => return bindings::TC_ACT_OK,
        };
        let proto: u8 = match ctx.load(l3_off + 9) {
            Ok(v) => v,
            Err(_) => return bindings::TC_ACT_OK,
        };
        let src_addr: u32 = match ctx.load(l3_off + 12) {
            Ok(v) => v,
            Err(_) => return bindings::TC_ACT_OK,
        };
        let dst_addr: u32 = match ctx.load(l3_off + 16) {
            Ok(v) => v,
            Err(_) => return bindings::TC_ACT_OK,
        };
        let iphdr_len = ((vihl & 0x0F) as usize) * 4;
        let (sp, dp) = read_ports_skb(&ctx, l3_off + iphdr_len, proto);
        let src_ip = u32::from_be(src_addr);
        let dst_ip = u32::from_be(dst_addr);
        let reply_key = FiveTuple::from_ipv4(dst_ip, src_ip, proto, dp, sp);
        let now = unsafe { bpf_ktime_get_ns() };
        let mut nv = CtValue::nat_reply();
        nv.last_seen = now;
        if CONNTRACK.insert(&reply_key, &nv, 0).is_ok() {
            info!(
                &ctx,
                "TC NAT LEARN family=4 reply_src={:i} reply_dport={}", dst_ip, sp
            );
        }
        bindings::TC_ACT_OK
    } else if ether_type == EtherType::Ipv6 as u16 {
        let proto: u8 = match ctx.load(l3_off + 6) {
            Ok(v) => v,
            Err(_) => return bindings::TC_ACT_OK,
        };
        let src_addr: [u8; 16] = match ctx.load(l3_off + 8) {
            Ok(v) => v,
            Err(_) => return bindings::TC_ACT_OK,
        };
        let dst_addr: [u8; 16] = match ctx.load(l3_off + 24) {
            Ok(v) => v,
            Err(_) => return bindings::TC_ACT_OK,
        };
        let (sp, dp) = read_ports_skb(&ctx, l3_off + Ipv6Hdr::LEN, proto);
        let reply_key = FiveTuple::from_ipv6(dst_addr, src_addr, proto, dp, sp);
        let now = unsafe { bpf_ktime_get_ns() };
        let mut nv = CtValue::nat_reply();
        nv.last_seen = now;
        if CONNTRACK.insert(&reply_key, &nv, 0).is_ok() {
            info!(&ctx, "TC NAT LEARN family=6 proto={}", proto);
        }
        bindings::TC_ACT_OK
    } else {
        bindings::TC_ACT_OK
    }
}

/// 用 `ctx.load`（固定长度 bpf_skb_load_bytes）读取 TCP/UDP 端口（非 TCP/UDP 返回 (0,0)）。
#[inline(always)]
fn read_ports_skb(ctx: &TcContext, l4_off: usize, proto: u8) -> (u16, u16) {
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return (0, 0);
    }
    let ports: u32 = match ctx.load(l4_off) {
        Ok(v) => v,
        Err(_) => return (0, 0),
    };
    let src_port = u16::from_be(ports as u16);
    let dst_port = u16::from_be((ports >> 16) as u16);
    (src_port, dst_port)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
