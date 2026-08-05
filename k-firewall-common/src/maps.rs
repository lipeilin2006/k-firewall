//! M2 VIF 抽象与连接跟踪 / QoS / 分片的 map 键/值类型。
//!
//! - `VIF_MAP`：`(物理接口 ifindex, 802.1Q VID)` -> VIF 配置，XDP 入口统一映射。
//! - `REDIRECT_DEV`（DevMap）：VIF ID -> 目标物理网卡，透明模式 `bpf_redirect` 用。
//! - `SURICATA_ALLOW_MAP`：Suricata 允许的返回流量五元组，eBPF 快速放行。
//! - `CONNTRACK`：五元组 -> 连接状态（双向匹配，见 `FiveTuple::reverse`）。
//! - `BLOCKED_MAP`：被封禁的源 IP（Suricata 联动 / CLI 封禁入口）。
//! - `FRAG_TRACK`：分片流（src/dst/proto）-> 最近活跃时刻，孤儿分片检测。
//! - `RATE_LIMITS`：per-source-IP 令牌桶（DDoS 防护）。
//! - `QOS_CLASSES` / `QOS_BUCKETS`：QoS 分类（DSCP 标记 + 每类入口限速）。

/// 接口模式：路由（普通三层转发 + SNAT）。
pub const MODE_ROUTE: u8 = 0;
/// 接口模式：透明（不改 IP/MAC/TTL，直接重定向到对端）。
pub const MODE_TRANSPARENT: u8 = 1;
/// 接口模式：混合。
pub const MODE_HYBRID: u8 = 2;

/// 地址族：IPv4。
pub const FAMILY_IPV4: u8 = 4;
/// 地址族：IPv6。
pub const FAMILY_IPV6: u8 = 6;

/// 接口角色：WAN。
pub const ROLE_WAN: u8 = 0;
/// 接口角色：LAN。
pub const ROLE_LAN: u8 = 1;
/// 接口角色：透明串接（inline）。
pub const ROLE_INLINE: u8 = 2;

// ============================================================================
// 连接跟踪状态（`CtValue.state` / `CT_TIMEOUTS` 槽位索引）
// ============================================================================
/// TCP：已发送 SYN（等待 SYN-ACK）。
pub const CT_STATE_TCP_SYN_SENT: u8 = 0;
/// TCP：收到 SYN-ACK（握手进行中）。
pub const CT_STATE_TCP_SYN_RECV: u8 = 1;
/// TCP：已建立（双向 ACK 完成）。
pub const CT_STATE_TCP_ESTABLISHED: u8 = 2;
/// TCP：一端已发 FIN。
pub const CT_STATE_TCP_FIN_WAIT: u8 = 3;
/// TCP：对端已发 FIN，本地还有数据要发。
pub const CT_STATE_TCP_CLOSE_WAIT: u8 = 4;
/// TCP：双向 FIN 完成，等待超时回收。
pub const CT_STATE_TCP_TIME_WAIT: u8 = 5;
/// UDP：无握手，收到即跟踪。
pub const CT_STATE_UDP: u8 = 6;
/// ICMP / ICMPv6：按 (src,dst,id) 跟踪。
pub const CT_STATE_ICMP: u8 = 7;
/// 其它 L4 协议：仅做五元组跟踪。
pub const CT_STATE_GENERIC: u8 = 8;

/// 连接跟踪状态总数（`CT_TIMEOUTS` 数组长度）。
pub const CT_STATE_MAX: usize = 9;

/// `CtValue.is_nat` 标记：条目由 TC Egress（masquerade 回程）或 DNAT 注入。
pub const CT_NAT_NONE: u8 = 0;
pub const CT_NAT_REPLY: u8 = 1;

/// `CtValue.counted` 位标志：该流已计入 `CONN_COUNT`（每源并发连接数）。
pub const CT_COUNTED_CONN: u8 = 0x01;
/// `CtValue.counted` 位标志：该流已计入 `SYN_COUNT`（每源半开连接数）。
pub const CT_COUNTED_SYN: u8 = 0x02;

/// 分片策略（`CONFIG` 槽位 `CONFIG_FRAGMENT_POLICY`）。
pub const FRAG_POLICY_PASS: u8 = 0;
pub const FRAG_POLICY_DROP: u8 = 1;
pub const FRAG_POLICY_INSPECT: u8 = 2;

// ============================================================================
// VIF 映射键值
// ============================================================================
/// `VIF_MAP` 键：物理接口 + VLAN。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VifKey {
    /// 物理网卡 ifindex。
    pub phy_ifindex: u32,
    /// 802.1Q VID（0 = 未打标）。
    pub vlan_id: u16,
    /// 对齐填充。
    pub _pad: u16,
}

/// `VIF_MAP` 值：单个 VIF 的配置。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VifConfig {
    /// 统一逻辑接口 ID（`REDIRECT_DEV` 索引）。
    pub vif_id: u16,
    /// `MODE_*`。
    pub mode: u8,
    /// `ROLE_*`。
    pub role: u8,
    /// 对端 VIF ID（透明/混合串接用）。
    pub peer_vif_id: u16,
    /// 该 VIF 的默认 SNAT 出口 IP（主机序；0 = 不 SNAT）。
    pub default_snat_ip: u32,
}

// ============================================================================
// IP 地址键（封禁 / 本机 IP 集合 / 分片流）
// ============================================================================
/// `BLOCKED` 表键：地址族 + 128 位 IP（IPv4 存前 4 字节，其余为 0）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpKey {
    /// `FAMILY_IPV4` / `FAMILY_IPV6`。
    pub family: u8,
    /// 对齐填充。
    pub _pad: [u8; 3],
    /// 网络序地址字节。
    pub ip: [u8; 16],
}

impl IpKey {
    pub fn from_ipv4(a: u32) -> Self {
        let mut ip = [0u8; 16];
        ip[0..4].copy_from_slice(&a.to_be_bytes());
        Self {
            family: FAMILY_IPV4,
            _pad: [0; 3],
            ip,
        }
    }

    pub fn from_ipv6(a: [u8; 16]) -> Self {
        Self {
            family: FAMILY_IPV6,
            _pad: [0; 3],
            ip: a,
        }
    }
}

/// `FRAG_TRACK` 表键：分片流标识（地址对 + 协议）。
///
/// 非首片分片不含 L4 头（端口不可读），因此以 (src, dst, proto) 标识所属流。
/// 首片 / 正常包在放行后向此表写入最近活跃时刻；非首片命中即视为属于已放行流。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragKey {
    /// `FAMILY_IPV4` / `FAMILY_IPV6`。
    pub family: u8,
    /// IP 协议号（IPPROTO_TCP/UDP/ICMP/...）。
    pub proto: u8,
    /// 对齐填充。
    pub _pad: [u8; 2],
    /// 网络序源地址。
    pub src_ip: [u8; 16],
    /// 网络序目的地址。
    pub dst_ip: [u8; 16],
}

impl FragKey {
    pub fn from_ipv4(src: u32, dst: u32, proto: u8) -> Self {
        let mut s = [0u8; 16];
        s[0..4].copy_from_slice(&src.to_be_bytes());
        let mut d = [0u8; 16];
        d[0..4].copy_from_slice(&dst.to_be_bytes());
        Self {
            family: FAMILY_IPV4,
            proto,
            _pad: [0; 2],
            src_ip: s,
            dst_ip: d,
        }
    }

    pub fn from_ipv6(src: [u8; 16], dst: [u8; 16], proto: u8) -> Self {
        Self {
            family: FAMILY_IPV6,
            proto,
            _pad: [0; 2],
            src_ip: src,
            dst_ip: dst,
        }
    }
}

// ============================================================================
// 五元组键（连接跟踪 + Suricata 允许列表 + NAT 学习）
// ============================================================================
/// `CONNTRACK` / `SURICATA_ALLOW_MAP` 键：纯五元组（不含入向 VIF，支持双向匹配）。
///
/// 双向匹配：返回包与原包源/目的互换，用 `reverse()` 得到反向键即可命中。
/// 地址统一存 16 字节（IPv4 存前 4 字节，其余为 0），family 区分。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    /// `FAMILY_IPV4` / `FAMILY_IPV6`。
    pub family: u8,
    /// IP 协议号（IPPROTO_TCP/UDP/ICMP/...）。
    pub proto: u8,
    /// 对齐填充。
    pub _pad: [u8; 2],
    /// 网络序地址字节。
    pub src_ip: [u8; 16],
    /// 网络序地址字节。
    pub dst_ip: [u8; 16],
    /// 网络序源端口（非 TCP/UDP 为 0）。
    pub src_port: u16,
    /// 网络序目的端口。
    pub dst_port: u16,
    /// 对齐填充。
    pub _pad2: u32,
}

impl FiveTuple {
    pub fn from_ipv4(src: u32, dst: u32, proto: u8, src_port: u16, dst_port: u16) -> Self {
        let mut s = [0u8; 16];
        s[0..4].copy_from_slice(&src.to_be_bytes());
        let mut d = [0u8; 16];
        d[0..4].copy_from_slice(&dst.to_be_bytes());
        Self {
            family: FAMILY_IPV4,
            proto,
            _pad: [0; 2],
            src_ip: s,
            dst_ip: d,
            src_port,
            dst_port,
            _pad2: 0,
        }
    }

    pub fn from_ipv6(
        src: [u8; 16],
        dst: [u8; 16],
        proto: u8,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            family: FAMILY_IPV6,
            proto,
            _pad: [0; 2],
            src_ip: src,
            dst_ip: dst,
            src_port,
            dst_port,
            _pad2: 0,
        }
    }

    /// 反向键：源/目的互换（返回包匹配用）。
    pub fn reverse(&self) -> Self {
        Self {
            family: self.family,
            proto: self.proto,
            _pad: [0; 2],
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            _pad2: 0,
        }
    }
}

// ============================================================================
// 连接跟踪值
// ============================================================================
/// `CONNTRACK` 表值：连接关联信息。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtValue {
    /// `CT_STATE_*`。
    pub state: u8,
    /// `CT_NAT_*`：1 = NAT 回程条目（TC Egress / DNAT 注入）。
    pub is_nat: u8,
    /// 1 = 该流携带分片（孤儿分片放行依据）。
    pub has_fragments: u8,
    /// 1 = 该流已计入 `CONN_COUNT`（防重复计数）。
    pub counted: u8,
    /// 上次活跃时刻（CLOCK_MONOTONIC，ns）。
    pub last_seen: u64,
    /// 本流累计包数（双向）。
    pub packets: u32,
    /// 原始方向（键方向）累计包数。
    pub pkts_orig: u32,
    /// 反向累计包数。
    pub pkts_repl: u32,
    /// 原始方向（键方向）累计字节数（整帧含 L2 头）。
    pub bytes_orig: u64,
    /// 反向累计字节数（整帧含 L2 头）。
    pub bytes_repl: u64,
    /// 对齐填充。
    pub _pad2: u32,
}

impl CtValue {
    /// 新建连接：按初始 TCP 状态或协议回退。
    pub fn new(state: u8) -> Self {
        Self {
            state,
            is_nat: CT_NAT_NONE,
            has_fragments: 0,
            counted: 0,
            last_seen: 0,
            packets: 0,
            pkts_orig: 0,
            pkts_repl: 0,
            bytes_orig: 0,
            bytes_repl: 0,
            _pad2: 0,
        }
    }

    /// NAT 回程条目（已建立）。
    pub fn nat_reply() -> Self {
        Self {
            state: CT_STATE_TCP_ESTABLISHED,
            is_nat: CT_NAT_REPLY,
            has_fragments: 0,
            counted: CT_COUNTED_CONN,
            last_seen: 0,
            packets: 0,
            pkts_orig: 0,
            pkts_repl: 0,
            bytes_orig: 0,
            bytes_repl: 0,
            _pad2: 0,
        }
    }
}

// ============================================================================
// DNAT 规则键值
// ============================================================================
/// `DNAT_RULES` 表键：入向（WAN 口 ingress）目的地址 + 端口 + 协议。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnatKey {
    /// 公网（WAN）目的 IP，网络序字节（IPv4 前 4 字节）。
    pub dst_ip: [u8; 16],
    /// 公网目的端口（网络序，与 FiveTuple 一致）。
    pub dst_port: u16,
    /// IP 协议号（IPPROTO_TCP=6 / UDP=17）。
    pub proto: u8,
    /// 对齐填充。
    pub _pad: u8,
}

impl DnatKey {
    pub fn from_ipv4(dst_ip: u32, dst_port: u16, proto: u8) -> Self {
        let mut d = [0u8; 16];
        d[0..4].copy_from_slice(&dst_ip.to_be_bytes());
        Self {
            dst_ip: d,
            dst_port,
            proto,
            _pad: 0,
        }
    }
}

/// `DNAT_RULES` 表值：转换目标（内部服务器）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnatValue {
    /// 内部服务器 IP（网络序字节，IPv4 前 4 字节）。
    pub to_ip: [u8; 16],
    /// 内部服务器端口（网络序）。
    pub to_port: u16,
    /// 对齐填充。
    pub _pad: [u8; 2],
}

impl DnatValue {
    pub fn from_ipv4(to_ip: u32, to_port: u16) -> Self {
        let mut t = [0u8; 16];
        t[0..4].copy_from_slice(&to_ip.to_be_bytes());
        Self {
            to_ip: t,
            to_port,
            _pad: [0; 2],
        }
    }
}

// ============================================================================
// 会话日志事件
// ============================================================================
/// 会话日志事件（`SESSION_LOG` RingBuf）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEvent {
    /// 事件动作：1=新建连接(NEW)，2=丢包(DROP)，3=封禁(BLOCKED)。
    pub action: u8,
    /// `FAMILY_IPV4` / `FAMILY_IPV6`。
    pub family: u8,
    /// IP 协议号。
    pub proto: u8,
    /// 源 VIF（物理接口）ifindex。
    pub ifindex: u32,
    /// 源端口（网络序）。
    pub src_port: u16,
    /// 目的端口（网络序）。
    pub dst_port: u16,
    /// 源地址（网络序字节，IPv4 前 4 字节）。
    pub src_ip: [u8; 16],
    /// 目的地址（网络序字节，IPv4 前 4 字节）。
    pub dst_ip: [u8; 16],
}

/// 会话事件动作：新建连接。
pub const SESSION_NEW: u8 = 1;
/// 会话事件动作：丢包。
pub const SESSION_DROP: u8 = 2;
/// 会话事件动作：封禁。
pub const SESSION_BLOCKED: u8 = 3;

impl SessionEvent {
    pub fn ipv4(
        action: u8,
        proto: u8,
        ifindex: u32,
        src: u32,
        dst: u32,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        let mut s = [0u8; 16];
        s[0..4].copy_from_slice(&src.to_be_bytes());
        let mut d = [0u8; 16];
        d[0..4].copy_from_slice(&dst.to_be_bytes());
        Self {
            action,
            family: FAMILY_IPV4,
            proto,
            ifindex,
            src_port,
            dst_port,
            src_ip: s,
            dst_ip: d,
        }
    }

    pub fn ipv6(
        action: u8,
        proto: u8,
        ifindex: u32,
        src: [u8; 16],
        dst: [u8; 16],
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            action,
            family: FAMILY_IPV6,
            proto,
            ifindex,
            src_port,
            dst_port,
            src_ip: src,
            dst_ip: dst,
        }
    }
}

// ============================================================================
// 速率限制（per-source-IP 令牌桶）
// ============================================================================
/// 源 IP 速率限制状态（`RATE_LIMITS` LRU map）。
///
/// 令牌桶：`rate` 为每秒令牌（pps），`burst` 为桶容量。XDP 在放行前对
/// 每个源 IP 扣一个令牌，不足即丢弃。条目由 daemon 预填（静态限速规则）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RateState {
    /// 上次令牌填充时刻（CLOCK_MONOTONIC，ns）。
    pub last: u64,
    /// 当前可用令牌数（≤ burst）。
    pub tokens: u32,
    /// 令牌补充速率（每秒令牌数）。
    pub rate: u32,
    /// 桶容量（突发上限）。
    pub burst: u32,
}

impl RateState {
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            last: 0,
            tokens: burst,
            rate,
            burst,
        }
    }
}

// ============================================================================
// QoS：分类配置 + 每类入口限速桶
// ============================================================================
/// QoS 分类的最大条目数（`QOS_CLASSES` / `QOS_BUCKETS` 数组长度）。
pub const QOS_MAX: u32 = 32;

/// `QOS_CLASSES` 值：单个 QoS 分类的匹配条件与 DSCP 目标。
///
/// 匹配：字段为 0 表示通配。首个匹配生效（按 `QOS_CLASSES` 顺序，配置序即优先级）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosConfig {
    /// 入向物理网卡 ifindex；0 = 任意接口。
    pub ingress_ifindex: u32,
    /// IP 协议号；0 = 任意。
    pub proto: u8,
    /// 对齐填充。
    pub _pad: [u8; 3],
    /// 源端口（网络序）；0 = 任意。
    pub src_port: u16,
    /// 目的端口（网络序）；0 = 任意。
    pub dst_port: u16,
    /// 目标 DSCP（0-63）。
    pub dscp: u8,
    /// 对齐填充。
    pub _pad2: [u8; 3],
    /// 每类入口限速（字节/秒）；0 = 不限速。
    pub rate_bps: u32,
    /// 桶容量（突发字节）。
    pub burst_bytes: u32,
}

/// `QOS_BUCKETS` 值：每类入口限速的令牌桶（per-CPU，无竞争）。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct QosBucket {
    /// 当前可用令牌（字节）。
    pub tokens: u32,
    /// 上次填充时刻（CLOCK_MONOTONIC，ns）。
    pub last: u64,
}

impl QosBucket {
    pub fn new() -> Self {
        Self::default()
    }
}

// ============================================================================
// P0：连接数配额 / SYN Flood / 协议助手（ALG）映射键值
// ============================================================================
/// `CONN_LIMITS` 表值：per-source-IP 最大并发连接数（0 = 不限制）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnLimit {
    /// 允许的最大并发连接数。
    pub max_conns: u32,
}

/// `SYN_LIMITS` 表值：per-source-IP SYN 令牌桶（每源 IP 新建连接速率）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SynState {
    /// 上次令牌填充时刻（CLOCK_MONOTONIC，ns）。
    pub last: u64,
    /// 当前可用令牌数。
    pub tokens: u32,
}

impl SynState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// `ALG_EXPECT` 表值：FTP 数据连接预期（`to` 方向五元组 -> 剩余寿命 ns）。
///
/// 预期条目由用户态 daemon 依据 Suricata eve `ftp` 事件写入（不再由 eBPF
/// 在载荷中扫描 PORT / 227 学习）；新建数据连接命中即放行并建立跟踪。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgExpect {
    /// 过期时刻（CLOCK_MONOTONIC，ns）；0 = 永不过期。
    pub expire_ns: u64,
}

// ============================================================================
// Zone 策略（有序数组条目）
// ============================================================================
/// Zone 策略最大条目数（`ZONE` 数组长度）。
///
/// 受 eBPF verifier 循环展开限制，数组不宜过大；64 条覆盖全部接口对（每条策略
/// 展开为 src→dst 与 dst→src 两条）仍绰绰有余。
pub const ZONE_MAX: u32 = 64;

/// `ZONE` 值：单条 Zone 策略（有序数组，首匹配生效）。
///
/// daemon 将策略按 id 升序写入 `ZONE` 数组（下标即执行顺序），eBPF 从 0 起
/// 顺序遍历，首个匹配 `(src_ifindex, dst 网段)` 的条目动作生效。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneEntry {
    /// 入向物理网卡 ifindex；0 = 任意接口。
    pub src_ifindex: u32,
    /// 目的网段（网络序字节，IPv4 前 4 字节）。
    pub dst_net: [u8; 16],
    /// 目的前缀长度（0 = 0.0.0.0/0 任意目的）。
    pub prefix_len: u8,
    /// `ACTION_DROP` / `ACTION_PASS`。
    pub action: u8,
    /// 对齐填充。
    pub _pad: [u8; 2],
}

impl ZoneEntry {
    pub fn from_ipv4(src_ifindex: u32, dst_net: u32, prefix_len: u8, action: u8) -> Self {
        let mut d = [0u8; 16];
        d[0..4].copy_from_slice(&dst_net.to_be_bytes());
        Self {
            src_ifindex,
            dst_net: d,
            prefix_len,
            action,
            _pad: [0; 2],
        }
    }
}

// ============================================================================
// aya::Pod（用户态 feature）
// ============================================================================
#[cfg(feature = "user")]
unsafe impl aya::Pod for VifKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for VifConfig {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FragKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FiveTuple {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CtValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnatKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnatValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateState {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for QosConfig {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for QosBucket {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnLimit {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SynState {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AlgExpect {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ZoneEntry {}
