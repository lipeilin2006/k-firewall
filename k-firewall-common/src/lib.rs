#![cfg_attr(not(feature = "api"), no_std)]

//! 内核态（eBPF）与用户态共享的类型与常量。
//!
//! - 默认 `#![no_std]`，供 `k-firewall-ebpf` 引用。
//! - `user` feature：为 eBPF map 键/值提供 `aya::Pod` 实现（daemon 使用）。
//! - `api` feature：提供 daemon 与 CLI 之间的 JSON 交互类型（隐含 std）。

/// 规则动作：丢弃。
pub const ACTION_DROP: u8 = 0;
/// 规则动作：放行。
pub const ACTION_PASS: u8 = 1;
/// 未命中任何规则时的默认动作。
pub const DEFAULT_ACTION: u8 = ACTION_PASS;

/// `CONFIG` map 槽位：默认动作。
pub const CONFIG_DEFAULT_ACTION: u32 = 0;
/// `CONFIG` map 槽位：分片策略（`maps::FRAG_POLICY_*`）。
pub const CONFIG_FRAGMENT_POLICY: u32 = 1;
/// `CONFIG` map 槽位：ICMPv6 RA / Redirect 过滤（0 关闭 / 1 开启）。
pub const CONFIG_RA_FILTER: u32 = 2;
/// `CONFIG` map 槽位：启用中的 QoS 分类数。
pub const CONFIG_QOS_COUNT: u32 = 3;
/// `CONFIG` map 槽位：`FRAG_TRACK` 条目的过期时长（秒）。
pub const CONFIG_FRAG_TIMEOUT: u32 = 4;
/// `CONFIG` map 槽位：SYN Flood 防护开关与每源 IP 速率（pps；0 = 关闭）。
pub const CONFIG_SYN_RATE: u32 = 5;
/// `CONFIG` map 槽位：SYN 令牌桶容量（突发上限）。
pub const CONFIG_SYN_BURST: u32 = 6;
/// `CONFIG` map 槽位：SYN Flood 防护每源 IP 半开连接数上限（0 = 不限制）。
pub const CONFIG_SYN_MAX_HALFOPEN: u32 = 7;
/// `CONFIG` map 槽位：FTP ALG 开关（0 关闭 / 1 开启，端口 21 控制流镜像）。
pub const CONFIG_FTP_ALG: u32 = 8;
/// `CONFIG` map 槽位：Suricata 规则头预过滤（0 关闭 / 1 开启）。
///
/// 开启后 XDP 对新建流按 `SURICATA_RULES`（LPM）做准入：未命中任一 Suricata
/// 规则头部的流直接丢弃（线速预过滤，只有需要 DPI 的流到达 Suricata）。
pub const CONFIG_SURICATA_PREFILTER: u32 = 9;

/// `BLOCKED` map 的 value 占位标记。
pub const BLOCKED_MARKER: u64 = 1;

/// M2 VIF 抽象与连接跟踪的 map 键/值类型。
pub mod maps;

/// 每 CPU 统计计数。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub packets: u64,
    pub passed: u64,
    pub dropped: u64,
    /// 被 `BLOCKED` 表直接丢弃的包（`dropped` 的子集）。
    pub blocked: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stats {}

/// daemon 侧维护的封禁记录（用户态）。
#[cfg(feature = "api")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    pub ip: std::net::IpAddr,
    pub reason: String,
    /// 添加时刻（unix 秒）。
    pub added_unix: u64,
    /// 过期时刻（unix 秒）；`None` 表示永久封禁。
    pub expire_unix: Option<u64>,
}

/// daemon 与 CLI 之间的 JSON API 类型。
#[cfg(feature = "api")]
pub mod api {
    use serde::{Deserialize, Serialize};

    use crate::Stats;

    /// GET /status
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Status {
        pub iface: String,
        pub attached: bool,
        pub rule_count: u64,
        pub blocked_count: u64,
        pub uptime_secs: u64,
    }

    /// GET /stats
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct StatsOut {
        pub packets: u64,
        pub passed: u64,
        pub dropped: u64,
        pub blocked: u64,
    }

    impl From<Stats> for StatsOut {
        fn from(s: Stats) -> Self {
            Self {
                packets: s.packets,
                passed: s.passed,
                dropped: s.dropped,
                blocked: s.blocked,
            }
        }
    }

    /// GET /blocked
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BlockRequest {
        pub ip: String,
        /// 封禁秒数；`None` = 永久。
        #[serde(default)]
        pub seconds: Option<u64>,
        #[serde(default)]
        pub reason: Option<String>,
    }

    /// GET /blocked
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BlockedEntryOut {
        pub ip: String,
        pub reason: String,
        pub added_unix: u64,
        pub expire_unix: Option<u64>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BlockedOut {
        pub entries: Vec<BlockedEntryOut>,
    }

    /// 统一错误响应体。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Error {
        pub error: String,
    }

    // ==========================================================================
    // Operational（运维查询）——`/api/v1/operational/*`
    // ==========================================================================

    /// GET /api/v1/operational/sessions：单条 Conntrack 会话。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SessionOut {
        /// 会话稳定标识（五元组十六进制编码），供 `DELETE /operational/sessions/{session_id}` 精确切断。
        pub session_id: String,
        pub family: String,
        pub proto: String,
        pub src_ip: String,
        pub src_port: u16,
        pub dst_ip: String,
        pub dst_port: u16,
        /// CT_STATE_* 名称（SYN_SENT / ESTABLISHED / UDP / ICMP / ...）。
        pub state: String,
    /// 1 = NAT 回程条目。
    pub is_nat: bool,
    pub packets: u32,
    /// 原始方向（键方向）包数。
    pub pkts_orig: u32,
    /// 反向包数。
    pub pkts_repl: u32,
    /// 原始方向（键方向）字节数（整帧含 L2 头）。
    pub bytes_orig: u64,
    /// 反向字节数（整帧含 L2 头）。
    pub bytes_repl: u64,
    /// 最近活跃时刻（CLOCK_MONOTONIC，ns）。
    pub last_seen_ns: u64,
    /// 距上次活跃的空闲秒数。
    pub idle_secs: u64,
    /// 距该会话被超时回收的剩余秒数（未配置超时的状态为 None）。
    pub expire_in_secs: Option<u64>,
    /// 最近活跃的 Unix 时间戳（秒；由 CLOCK_MONOTONIC + 开机偏移换算）。
    pub last_seen_unix: u64,
    /// Suricata 检测到的应用层协议（如 http/tls/dns/ssh；未检测为 None）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_proto: Option<String>,
    /// TLS 指纹（JA3/JA3S，Suricata `tls.fingerprint`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<String>,
    /// TLS SNI（ClientHello 中的服务器名）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_sni: Option<String>,
    /// HTTP Host 头。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_host: Option<String>,
    /// HTTP User-Agent。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_user_agent: Option<String>,
    /// DNS 查询名。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_query: Option<String>,
    /// Suricata 会话信息（如 TLS 版本 / HTTP 方法 / DNS 类型）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_info: Option<String>,
}

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SessionsOut {
        pub total: usize,
        pub entries: Vec<SessionOut>,
    }

    /// GET /api/v1/operational/blocklist：单条封禁记录。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BlocklistEntryOut {
        pub ip: String,
        pub reason: String,
        pub added_unix: u64,
        pub expire_unix: Option<u64>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct BlocklistOut {
        pub entries: Vec<BlocklistEntryOut>,
    }

    // ==========================================================================
    // Suricata Rules（L4 规则头预过滤）——`/api/v1/suricata/rules`
    // ==========================================================================

    /// 单条 Suricata 规则输出（`id` 供 DELETE 使用）。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SuricataRuleOut {
        /// 规则 id。
        pub id: u64,
        /// 原始 Suricata 规则文本。
        pub suricata_str: String,
        /// 规则是否启用：`false` 时不参与预过滤（等于临时关闭，未删除）。
        pub enabled: bool,
        /// 该规则是否成功下发为 eBPF 预过滤条目。
        pub prefilter: bool,
        /// 预过滤下发失败原因（IPv6 规则、取反地址/端口等）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub prefilter_note: Option<String>,
    }

    /// POST /api/v1/suricata/rules：新增一条 Suricata 规则。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SuricataRuleRequest {
        /// 完整的 Suricata 规则文本（单行）。
        pub rule: String,
    }

    /// PUT /api/v1/suricata/rules/{id}：原地更新一条规则（重新解析头部并重载预过滤）。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SuricataRuleUpdateRequest {
        /// 新的完整 Suricata 规则文本（单行）。
        pub rule: String,
    }

    /// PATCH /api/v1/suricata/rules/{id}：部分更新（启用/禁用）。
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct SuricataRulePatchRequest {
        /// 是否启用该规则参与预过滤（None = 不修改）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
    }

    /// DELETE /api/v1/suricata/rules：按 id 批量删除。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SuricataRuleDeleteRequest {
        pub ids: Vec<u64>,
    }

    /// POST /api/v1/suricata/rules/import：批量导入。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SuricataRuleImportRequest {
        /// 规则文本列表（每条一行）。
        pub rules: Vec<String>,
    }

    /// GET /api/v1/suricata/rules 分页结果。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SuricataRuleListOut {
        /// 匹配查询条件的规则总数（分页前）。
        pub total: usize,
        pub entries: Vec<SuricataRuleOut>,
    }

    /// 批量导入结果。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SuricataRuleImportOut {
        /// 本次处理的总条数。
        pub total: usize,
        /// 成功添加的条数。
        pub added: usize,
        /// 失败的条数。
        pub failed: usize,
        /// 失败原因（与失败条目一一对应，含原始文本前缀）。
        pub errors: Vec<String>,
        /// 当前全部规则。
        pub rules: Vec<SuricataRuleOut>,
    }

    // ==========================================================================
    // API 层补齐（主流防火墙对齐）：会话删除 / 预过滤统计 / 系统
    // ==========================================================================

    /// 会话删除过滤器（DELETE /api/v1/operational/sessions，全空 = 清空全部）。
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct SessionDeleteRequest {
        /// ipv4 | ipv6。
        #[serde(default)]
        pub family: Option<String>,
        /// tcp | udp | icmp | icmp6。
        #[serde(default)]
        pub proto: Option<String>,
        #[serde(default)]
        pub src_ip: Option<String>,
        #[serde(default)]
        pub dst_ip: Option<String>,
        #[serde(default)]
        pub src_port: Option<u16>,
        #[serde(default)]
        pub dst_port: Option<u16>,
        /// 源地址 CIDR（如 `192.168.10.0/24`，无前缀按 /32 处理）。
        #[serde(default)]
        pub src_cidr: Option<String>,
        /// 目的地址 CIDR。
        #[serde(default)]
        pub dst_cidr: Option<String>,
    }

    /// 会话删除结果。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SessionsDeleteOut {
        pub removed: usize,
    }

    /// GET /api/v1/suricata/prefilter/stats：规则头预过滤状态与表容量。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SuricataPrefilterStats {
        /// `CONFIG_SURICATA_PREFILTER` 是否开启（配置开启 && 存在可表达规则）。
        pub enabled: bool,
        /// 4 张表中元组总数。
        pub tuples_total: u64,
        /// 13B `SURICATA_RULES_DST`（src 精确）条目数。
        pub dst: u64,
        /// 9B `SURICATA_RULES_DST_ANY`（src 通配）条目数。
        pub dst_any: u64,
        /// 13B `SURICATA_RULES_SRC`（dst 精确）条目数。
        pub src: u64,
        /// 9B `SURICATA_RULES_SRC_ANY`（dst 通配）条目数。
        pub src_any: u64,
    }

    /// GET /api/v1/system/interfaces：单条逻辑接口信息。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InterfaceInfo {
        /// 逻辑接口名。
        pub name: String,
        /// wan | lan | inline。
        pub role: String,
        /// route | transparent | hybrid。
        pub mode: String,
        /// NAT 模式：none | masquerade。
        pub nat: String,
        /// IPv4 地址（未配置为 None）。
        pub address: Option<String>,
        /// 子网掩码（未配置为 None）。
        pub netmask: Option<String>,
        /// 内核 ifindex（不存在为 0）。
        pub ifindex: u32,
        /// MAC 地址（读取失败为 None）。
        pub mac: Option<String>,
        /// 链路是否 up。
        pub carrier: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InterfacesOut {
        pub entries: Vec<InterfaceInfo>,
    }

    /// GET /api/v1/operational/stats/interfaces：单网卡 sysfs 统计。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InterfaceStats {
        pub name: String,
        pub rx_packets: u64,
        pub rx_bytes: u64,
        pub rx_dropped: u64,
        pub tx_packets: u64,
        pub tx_bytes: u64,
        pub tx_dropped: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct InterfaceStatsOut {
        pub entries: Vec<InterfaceStats>,
    }

    /// GET /api/v1/system/config：当前配置备份（text/plain 由 handler 直接返回）。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConfigRestoreOut {
        pub accepted: bool,
        /// 变更说明（如 "config written; restart required for full effect"）。
        pub message: String,
    }

    /// POST /api/v1/system/config/validate：配置校验结果。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConfigValidateOut {
        /// YAML 是否合法。
        pub valid: bool,
        /// 校验错误（valid=false 时）。
        pub errors: Vec<String>,
    }

    /// POST /api/v1/system/config/diff：YAML 语义差异。
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConfigDiffOut {
        /// 传入配置是否合法（无效时无意义）。
        pub valid: bool,
        /// 变更的顶层键（前导 + 表示新增语义差异，见下说明）。
        pub changed_keys: Vec<String>,
        /// 差异描述（可读文本行）。
        pub summary: Vec<String>,
    }

    /// GET /api/v1/operational/sessions 排序/分页查询参数。
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct SessionListQuery {
        /// ipv4 | ipv6。
        #[serde(default)]
        pub family: Option<String>,
        /// tcp | udp | icmp | icmp6。
        #[serde(default)]
        pub proto: Option<String>,
        #[serde(default)]
        pub src_ip: Option<String>,
        #[serde(default)]
        pub dst_ip: Option<String>,
        #[serde(default)]
        pub src_port: Option<u16>,
        #[serde(default)]
        pub dst_port: Option<u16>,
        /// 源地址 CIDR（如 `192.168.10.0/24`，无前缀按 /32 处理）。
        #[serde(default)]
        pub src_cidr: Option<String>,
        /// 目的地址 CIDR。
        #[serde(default)]
        pub dst_cidr: Option<String>,
        /// 应用层协议（http/tls/dns/ssh...）。
        #[serde(default)]
        pub app_proto: Option<String>,
        /// TLS SNI 关键字（子串匹配）。
        #[serde(default)]
        pub tls_sni: Option<String>,
        /// HTTP Host 关键字。
        #[serde(default)]
        pub http_host: Option<String>,
        /// DNS 查询名关键字。
        #[serde(default)]
        pub dns_query: Option<String>,
        /// 连接状态名（SYN_SENT/ESTABLISHED/UDP/ICMP...）。
        #[serde(default)]
        pub state: Option<String>,
        /// 全局关键字：同时匹配 SNI / Host / DNS / app_info / IP。
        #[serde(default)]
        pub q: Option<String>,
        /// 页码（1 起；默认 1）。
        #[serde(default)]
        pub page: Option<usize>,
        /// 每页条数（默认 100，上限 1000）。
        #[serde(default)]
        pub limit: Option<usize>,
        /// 排序字段：state | packets | bytes | last_seen（默认 last_seen）。
        #[serde(default)]
        pub sort: Option<String>,
    }
}
