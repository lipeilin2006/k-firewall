use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use k_firewall_common::maps::{MODE_ROUTE, MODE_TRANSPARENT, ROLE_INLINE, ROLE_WAN, VifConfig};
use serde::Deserialize;
use tracing::warn;

use crate::ebpf_loader::Action;

/// NAT 模式：关闭。
pub const NAT_NONE: u8 = 0;
/// NAT 模式：出口接口 masquerade（自动伪装为当前出口 IP）。
pub const NAT_MASQUERADE: u8 = 1;

/// 端口转发（DNAT）规则：`(dst_ip:dst_port, proto)` -> `to_ip:to_port`。
///
/// 目的 IP 为 WAN 口公网 IP；XDP 命中后向 CONNTRACK_NAT 注入回程 key 供回程放行，
/// 实际 DNAT 改写由内核 nftables `prerouting dnat` 完成。
#[derive(Debug, Clone, Deserialize)]
pub struct DnatRule {
    /// 公网（WAN）目的 IP（IPv4）。
    pub dst_ip: Ipv4Addr,
    /// 公网目的端口。
    pub dst_port: u16,
    /// tcp | udp。
    #[serde(default = "default_dnat_proto")]
    pub proto: String,
    /// 内部服务器 IP（IPv4）。
    pub to_ip: Ipv4Addr,
    /// 内部服务器端口。
    pub to_port: u16,
}

fn default_dnat_proto() -> String {
    "tcp".into()
}

impl DnatRule {
    pub fn proto_u8(&self) -> Result<u8> {
        Ok(match self.proto.as_str() {
            "tcp" => 6,
            "udp" => 17,
            other => bail!("dnat proto unsupported {other:?} (tcp|udp)"),
        })
    }

    fn validate(&self) -> Result<()> {
        self.proto_u8()?;
        if self.dst_port == 0 || self.to_port == 0 {
            bail!("dnat: dst_port/to_port must be nonzero");
        }
        Ok(())
    }
}

/// 计算 IPv4 掩码的前缀位数（255.255.255.0 -> 24）。
fn mask_bits(mask: Ipv4Addr) -> u32 {
    u32::from(mask).count_ones()
}

/// 主配置（YAML SSOT）。
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub global: Global,
    /// 接口（VIF）定义；为空时回退到顶层 `interface` 的单接口配置。
    #[serde(default)]
    pub interfaces: Vec<InterfaceConfig>,
    #[serde(default)]
    pub wan_groups: Vec<WanGroup>,
    #[serde(default)]
    pub pbr_rules: Vec<PbrRule>,
    #[serde(default)]
    pub zone_policies: Vec<ZonePolicy>,
    /// 未命中任何规则时的默认动作：pass | drop。
    #[serde(default = "default_action_str")]
    pub default_action: String,
    /// XDP 挂载模式：generic | native | hardware | auto。
    #[serde(default = "default_xdp_mode")]
    pub xdp_mode: String,
    /// 统计打印间隔（秒）。
    #[serde(default = "default_stats_interval")]
    pub stats_interval_secs: u64,
    #[serde(default)]
    pub daemon: Daemon,
    #[serde(default)]
    pub suricata: Suricata,
    #[serde(default)]
    pub multiwan: Multiwan,
    /// 会话日志：将新建连接 / 丢包 / 封禁事件输出到 daemon 日志（可选转发 syslog）。
    #[serde(default)]
    pub session_log: SessionLog,
    /// 源 IP 速率限制规则（每源 IP 令牌桶，pps / 突发）。
    #[serde(default)]
    pub rate_limit_rules: Vec<RateLimitRule>,
    /// 每源 IP 并发连接数上限（0 = 不限）。
    #[serde(default)]
    pub conn_limits: Vec<ConnLimitRule>,
    /// SYN Flood 防护（每源 IP 新建连接令牌桶 + 半开上限）。
    #[serde(default)]
    pub syn_flood: SynFlood,
    /// 协议助手（ALG）：FTP 控制流学习数据连接。
    #[serde(default)]
    pub alg: Alg,
    /// 端口转发（DNAT）规则。
    #[serde(default)]
    pub nat_rules: Vec<DnatRule>,
    /// 分片策略：pass（交给内核重组）| drop（丢弃全部分片）| inspect（孤儿分片丢弃）。
    #[serde(default = "default_fragment_policy")]
    pub fragment_policy: String,
    /// `FRAG_TRACK` 分片流条目的过期时长（秒）。
    #[serde(default = "default_fragment_timeout")]
    pub fragment_timeout_secs: u64,
    /// 连接跟踪（完整 TCP 状态机 + 每状态超时）。
    #[serde(default)]
    pub conntrack: Conntrack,
    /// IPv6 安全：RA / Redirect 过滤（防路由注入）。
    #[serde(default)]
    pub ipv6: Ipv6,
    /// QoS：DSCP 分类 / 每类入口限速 / 出口整形。
    #[serde(default)]
    pub qos: Qos,
    /// 遗留单接口字段（interfaces 为空时使用）。
    #[serde(default = "default_iface")]
    pub interface: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            warn!("config {} not found, using defaults", path.display());
            return Ok(Config::default());
        }
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        Self::from_str(&text).with_context(|| format!("failed to parse config {}", path.display()))
    }

    /// 从 YAML 字符串解析并校验配置（`POST /api/v1/system/config` 恢复用）。
    pub fn from_str(text: &str) -> Result<Self> {
        let cfg: Config = serde_yaml_ng::from_str(text).context("failed to parse config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        Action::from_str(&self.default_action)?;
        for (i, dnat) in self.nat_rules.iter().enumerate() {
            dnat.validate().with_context(|| format!("nat_rules[{i}]"))?;
        }
        for (i, rl) in self.rate_limit_rules.iter().enumerate() {
            rl.validate()
                .with_context(|| format!("rate_limit_rules[{i}]"))?;
        }
        for (i, cl) in self.conn_limits.iter().enumerate() {
            cl.validate().with_context(|| format!("conn_limits[{i}]"))?;
        }
        self.syn_flood.validate().context("syn_flood")?;
        if self.stats_interval_secs == 0 {
            bail!("stats_interval_secs must be > 0");
        }

        // 分片策略。
        match self.fragment_policy.as_str() {
            "pass" | "drop" | "inspect" => {}
            other => bail!("unsupported fragment_policy {other:?} (pass|drop|inspect)"),
        }
        if self.fragment_timeout_secs == 0 {
            bail!("fragment_timeout_secs must be > 0");
        }

        // 接口名唯一（QoS 的 ingress_iface 引用据此校验）。
        let mut names: HashSet<&str> = HashSet::new();
        for (i, ifc) in self.interfaces.iter().enumerate() {
            if !names.insert(ifc.name.as_str()) {
                bail!("interfaces[{i}]: duplicate name {:?}", ifc.name);
            }
            ifc.validate()?;
        }

        // QoS 校验。
        let mut qos_names: HashSet<&str> = HashSet::new();
        for (i, c) in self.qos.classes.iter().enumerate() {
            if !qos_names.insert(c.name.as_str()) {
                bail!("qos.classes[{i}]: duplicate name {:?}", c.name);
            }
            c.validate().with_context(|| format!("qos.classes[{i}]"))?;
            if let Some(iface) = &c.ingress_iface {
                if !names.contains(iface.as_str()) {
                    bail!("qos.classes[{i}]: unknown ingress_iface {iface:?}");
                }
            }
        }
        // peer 必须引用已存在接口。
        for (i, ifc) in self.interfaces.iter().enumerate() {
            if let Some(peer) = &ifc.peer {
                if !names.contains(peer.as_str()) {
                    bail!("interfaces[{i}] {:?}: unknown peer {peer:?}", ifc.name);
                }
            }
            // 透明/混合串接必须有对端。
            if ifc.mode_u8()? != MODE_ROUTE && ifc.peer.is_none() {
                bail!(
                    "interfaces[{i}] {:?}: mode {:?} requires a peer",
                    ifc.name,
                    ifc.mode
                );
            }
        }
        // wan_groups 成员必须引用已存在接口。
        for (i, g) in self.wan_groups.iter().enumerate() {
            for m in &g.members {
                if !names.contains(m.name.as_str()) {
                    bail!("wan_groups[{i}] {:?}: unknown member {:?}", g.name, m.name);
                }
            }
        }
        // zone_policies 引用必须存在。
        for (i, p) in self.zone_policies.iter().enumerate() {
            if !names.contains(p.src_interface.as_str()) {
                bail!(
                    "zone_policies[{i}]: unknown src_interface {:?}",
                    p.src_interface
                );
            }
            if !names.contains(p.dst_interface.as_str()) {
                bail!(
                    "zone_policies[{i}]: unknown dst_interface {:?}",
                    p.dst_interface
                );
            }
            match p.action.as_str() {
                "accept" | "drop" => {}
                other => bail!("zone_policies[{i}]: unsupported action {other:?} (accept|drop)"),
            }
        }
        Ok(())
    }

    /// 归一化：interfaces 为空时用遗留 `interface` 字段合成单接口配置。
    /// 解析后 / `-i` 覆盖后各调用一次。
    pub fn normalize(&mut self) {
        if self.interfaces.is_empty() {
            let name = if self.interface.is_empty() {
                "lan0".to_string()
            } else {
                self.interface.clone()
            };
            self.interfaces.push(InterfaceConfig {
                name,
                role: "wan".into(),
                mode: "route".into(),
                nat: "none".into(),
                address: None,
                netmask: None,
                gateway: None,
                parent: None,
                vlan_id: None,
                peer: None,
                dhcp_server: None,
                nat6: None,
                dhcp6_server: None,
            });
        }
    }

    /// 解析后的默认动作（已校验）。
    pub fn default_action(&self) -> Action {
        Action::from_str(&self.default_action).expect("config validated")
    }

    /// 主接口名（API /status 展示用）。
    pub fn primary_iface(&self) -> String {
        self.interfaces
            .first()
            .map(|i| i.name.clone())
            .unwrap_or_else(|| self.interface.clone())
    }

    /// 需要挂载 XDP 的物理网卡（去重，保序）。
    pub fn attach_ifaces(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for ifc in &self.interfaces {
            let phy = ifc.phy_name();
            if seen.insert(phy.clone()) {
                out.push(phy);
            }
        }
        out
    }

    /// 需要挂载 TC Egress 学习程序的物理网卡（route 模式 + masquerade 的出口，
    /// 去重，保序）。TC egress 在 POSTROUTING 之后执行，可看到 NAT 后的五元组。
    pub fn nat_egress_ifaces(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for ifc in &self.interfaces {
            if ifc.nat == "masquerade" && ifc.mode == "route" {
                let phy = ifc.phy_name();
                if seen.insert(phy.clone()) {
                    out.push(phy);
                }
            }
        }
        out
    }

    /// 需要做 IPv6 masquerade（NAT66）的出口物理网卡（route 模式 + `nat6: masquerade`）。
    pub fn nat6_egress_ifaces(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for ifc in &self.interfaces {
            if ifc.mode == "route" && ifc.nat6.as_deref().unwrap_or("none") == "masquerade" {
                let phy = ifc.phy_name();
                if seen.insert(phy.clone()) {
                    out.push(phy);
                }
            }
        }
        out
    }

    /// 展开后的 QoS 分类（`QOS_CLASSES` map）：逻辑接口名解析为 ifindex 的
    /// 工作由 loader 完成，此处只输出逻辑名 + 匹配条件。
    pub fn qos_entries(&self) -> Vec<k_firewall_common::maps::QosConfig> {
        let mut out = Vec::new();
        for c in &self.qos.classes {
            let ingress_ifindex = match &c.ingress_iface {
                Some(name) => self
                    .interfaces
                    .iter()
                    .find(|i| &i.name == name)
                    .and_then(|i| {
                        std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", i.phy_name()))
                            .ok()
                    })
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(0),
                None => 0,
            };
            let proto = c.proto_u8().unwrap_or(0);
            out.push(k_firewall_common::maps::QosConfig {
                ingress_ifindex,
                proto,
                _pad: [0; 3],
                src_port: c.src_port.to_be(),
                dst_port: c.dst_port.to_be(),
                dscp: c.dscp,
                _pad2: [0; 3],
                rate_bps: c.rate_bps.min(u32::MAX as u64) as u32,
                burst_bytes: c.burst_bytes,
            });
        }
        out
    }

    /// 展开后的 VIF 列表：(物理网卡, VLAN ID, VifConfig)。
    ///
    /// `vif_id` 为 interfaces 列表顺序索引，同时是 `REDIRECT_DEV` 索引。
    pub fn vifs(&self) -> Vec<(String, u16, VifConfig)> {
        self.interfaces
            .iter()
            .enumerate()
            .map(|(idx, ifc)| {
                let peer_vif_id = ifc
                    .peer
                    .as_ref()
                    .and_then(|p| self.interfaces.iter().position(|o| &o.name == p))
                    .map(|i| i as u16)
                    .unwrap_or(0);
                (
                    ifc.phy_name(),
                    ifc.vlan_id.unwrap_or(0),
                    ifc.to_vif_config(idx as u16, peer_vif_id),
                )
            })
            .collect()
    }

    /// 编译后的 Zone 策略条目：`(src 物理网卡, dst IP, 前缀长度, 动作)`。
    ///
    /// dst 网段由 `dst_interface` 的 `address`/`netmask` 推导（默认 /24）；
    /// 无 address（transparent 对等）回退到 0.0.0.0/0（匹配任意目的）。
    /// 每条策略生成双向条目（src→dst 与 dst→src），实现 zone 双向语义。
    /// eBPF 侧用 LpmTrie 按 `(src_ifindex, dst_ip)` 最长前缀匹配。
    pub fn zone_entries(&self) -> Vec<(String, u32, u32, u8)> {
        let mut out = Vec::new();
        for z in &self.zone_policies {
            let Some(src) = self.interfaces.iter().find(|i| &i.name == &z.src_interface) else {
                continue;
            };
            let Some(dst) = self.interfaces.iter().find(|i| &i.name == &z.dst_interface) else {
                continue;
            };
            let action = match z.action.as_str() {
                "drop" => k_firewall_common::ACTION_DROP,
                _ => k_firewall_common::ACTION_PASS,
            };
            // src 侧网段（用于反向条目）：无 address 则 0.0.0.0/0。
            let (src_net, src_prefix) = match src.address {
                Some(addr) => {
                    let mask = src.netmask.unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
                    (u32::from(addr) & u32::from(mask), mask_bits(mask))
                }
                None => (0u32, 0u32),
            };
            let (dst_net, dst_prefix) = match dst.address {
                Some(addr) => {
                    let mask = dst.netmask.unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
                    (u32::from(addr) & u32::from(mask), mask_bits(mask))
                }
                None => (0u32, 0u32),
            };
            // 正向：src -> dst 网段。
            out.push((src.phy_name(), dst_net, dst_prefix, action));
            // 反向：dst -> src 网段。
            out.push((dst.phy_name(), src_net, src_prefix, action));
        }
        out
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            global: Global::default(),
            interfaces: Vec::new(),
            wan_groups: Vec::new(),
            pbr_rules: Vec::new(),
            zone_policies: Vec::new(),
            default_action: "pass".into(),
            xdp_mode: "generic".into(),
            stats_interval_secs: 5,
            daemon: Daemon::default(),
            suricata: Suricata::default(),
            multiwan: Multiwan::default(),
            session_log: SessionLog::default(),
            rate_limit_rules: Vec::new(),
            conn_limits: Vec::new(),
            syn_flood: SynFlood::default(),
            alg: Alg::default(),
            nat_rules: Vec::new(),
            fragment_policy: default_fragment_policy(),
            fragment_timeout_secs: default_fragment_timeout(),
            conntrack: Conntrack::default(),
            ipv6: Ipv6::default(),
            qos: Qos::default(),
            interface: "lan0".into(),
        }
    }
}

fn default_iface() -> String {
    "lan0".into()
}

fn default_nat6() -> Option<String> {
    None
}

fn default_fragment_policy() -> String {
    "pass".into()
}

fn default_fragment_timeout() -> u64 {
    60
}

fn default_action_str() -> String {
    "pass".into()
}

fn default_xdp_mode() -> String {
    "generic".into()
}

fn default_stats_interval() -> u64 {
    5
}

/// 全局元信息。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Global {
    pub node_name: String,
}

impl Default for Global {
    fn default() -> Self {
        Self {
            node_name: "k-firewall".into(),
        }
    }
}

/// 接口（VIF）定义。
#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceConfig {
    /// 逻辑名；无 `parent` 时也是物理网卡名。
    pub name: String,
    /// wan | lan | inline。
    #[serde(default = "default_role")]
    pub role: String,
    /// route | transparent | hybrid。
    #[serde(default = "default_mode")]
    pub mode: String,
    /// NAT 模式：none | masquerade（仅 route 模式出口接口有意义）。
    #[serde(default = "default_nat")]
    pub nat: String,
    /// IPv4 地址（路由模式用；同时是默认 SNAT 出口 IP）。
    pub address: Option<Ipv4Addr>,
    /// 网络掩码（zone 策略推导网段用；默认 /24）。
    pub netmask: Option<Ipv4Addr>,
    /// 网关（可选）。
    pub gateway: Option<Ipv4Addr>,
    /// 物理宿主接口（VLAN 子接口时必填）。
    pub parent: Option<String>,
    /// 802.1Q VID（0 / None = 未打标）。
    pub vlan_id: Option<u16>,
    /// 对端接口名（inline 透明/混合串接必填）。
    pub peer: Option<String>,
    /// 是否启用 DHCP 服务（占位，后续实现）。
    pub dhcp_server: Option<String>,
    /// IPv6 NAT 模式：none | masquerade（仅 route 模式出口接口有意义）。
    #[serde(default = "default_nat6")]
    pub nat6: Option<String>,
    /// 是否启用 DHCPv6 服务（IPv6 地址池，如 "2001:db8:1::/64"）。
    pub dhcp6_server: Option<String>,
}

fn default_role() -> String {
    "lan".into()
}

fn default_mode() -> String {
    "route".into()
}

fn default_nat() -> String {
    "none".into()
}

impl InterfaceConfig {
    fn validate(&self) -> Result<()> {
        self.role_u8()?;
        self.mode_u8()?;
        self.nat_u8()?;
        self.nat6_u8()?;
        if self.parent.is_some() && self.vlan_id.is_none() {
            bail!("{:?}: parent set but vlan_id missing", self.name);
        }
        if self.vlan_id.is_some() {
            let vid = self.vlan_id.unwrap();
            if vid == 0 || vid > 4094 {
                bail!("{:?}: vlan_id out of range 1..4094", self.name);
            }
        }
        Ok(())
    }

    fn role_u8(&self) -> Result<u8> {
        Ok(match self.role.as_str() {
            "wan" => ROLE_WAN,
            "lan" => k_firewall_common::maps::ROLE_LAN,
            "inline" => ROLE_INLINE,
            other => bail!(
                "{:?}: unsupported role {other:?} (wan|lan|inline)",
                self.name
            ),
        })
    }

    pub fn mode_u8(&self) -> Result<u8> {
        Ok(match self.mode.as_str() {
            "route" => MODE_ROUTE,
            "transparent" => MODE_TRANSPARENT,
            "hybrid" => k_firewall_common::maps::MODE_HYBRID,
            other => bail!(
                "{:?}: unsupported mode {other:?} (route|transparent|hybrid)",
                self.name
            ),
        })
    }

    /// NAT 模式编号：0 = none，1 = masquerade。
    pub fn nat_u8(&self) -> Result<u8> {
        Ok(match self.nat.as_str() {
            "none" => NAT_NONE,
            "masquerade" => NAT_MASQUERADE,
            other => bail!(
                "{:?}: unsupported nat {other:?} (none|masquerade)",
                self.name
            ),
        })
    }

    /// IPv6 NAT 模式：0 = none，1 = masquerade。
    pub fn nat6_u8(&self) -> Result<u8> {
        Ok(match self.nat6.as_deref().unwrap_or("none") {
            "none" => NAT_NONE,
            "masquerade" => NAT_MASQUERADE,
            other => bail!(
                "{:?}: unsupported nat6 {other:?} (none|masquerade)",
                self.name
            ),
        })
    }

    /// 物理网卡名：有 parent 用 parent，否则用自身。
    pub fn phy_name(&self) -> String {
        self.parent.clone().unwrap_or_else(|| self.name.clone())
    }

    fn to_vif_config(&self, vif_id: u16, peer_vif_id: u16) -> VifConfig {
        VifConfig {
            vif_id,
            mode: self.mode_u8().expect("config validated"),
            role: self.role_u8().expect("config validated"),
            peer_vif_id,
            default_snat_ip: self.address.map(u32::from).unwrap_or(0),
        }
    }
}

/// 多 WAN 组。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WanGroup {
    pub name: String,
    /// 成员（接口名 + 权重）。
    pub members: Vec<WanMember>,
    /// 负载均衡算法：weighted_hash | failover。
    pub load_balance: String,
    /// 是否启用故障切换。
    pub failover: bool,
    /// 健康检查配置。
    pub health_check: Option<HealthCheck>,
}

impl Default for WanGroup {
    fn default() -> Self {
        Self {
            name: String::new(),
            members: Vec::new(),
            load_balance: "weighted_hash".into(),
            failover: true,
            health_check: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WanMember {
    pub name: String,
    /// 权重（越大越优先）。
    pub weight: u32,
}

impl Default for WanMember {
    fn default() -> Self {
        Self {
            name: String::new(),
            weight: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HealthCheck {
    /// 探活目标 IP（字符串）。
    pub probe_target: String,
    pub probe_port: u16,
    /// 探活间隔（秒）。
    pub interval_secs: u64,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            probe_target: "8.8.8.8".into(),
            probe_port: 53,
            interval_secs: 5,
        }
    }
}

/// 策略路由规则（M2 阶段仅解析，后续实现）。
#[derive(Debug, Clone, Deserialize)]
pub struct PbrRule {
    pub src_net: Option<String>,
    pub dst_net: Option<String>,
    pub use_wan: Option<String>,
    pub use_wan_group: Option<String>,
}

/// 区域策略（M2 阶段仅解析，后续实现）。
#[derive(Debug, Clone, Deserialize)]
pub struct ZonePolicy {
    pub src_interface: String,
    pub dst_interface: String,
    pub action: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Daemon {
    /// daemon 与 CLI 之间的 Unix Domain Socket 路径。
    pub unix_socket: PathBuf,
    /// TCP HTTP API 监听地址（如 "0.0.0.0:8080"）；空 / 未配置 = 只开 Unix socket。
    pub http_addr: Option<String>,
    /// SQLite 数据库路径（运行时增删的规则持久化；空 / 未配置 = 不持久化）。
    pub db_path: Option<PathBuf>,
    /// HTTP API 认证 Key 列表。配置后所有 `/api/v1` 请求必须带
    /// `Authorization: Bearer <key>` 或 `X-API-Key: <key>`；空 = 不启用认证（保持兼容）。
    pub api_keys: Vec<String>,
}

impl Default for Daemon {
    fn default() -> Self {
        Self {
            unix_socket: PathBuf::from("/var/run/k-firewall.sock"),
            http_addr: None,
            db_path: None,
            api_keys: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Suricata {
    pub enabled: bool,
    /// 优先使用的 eve Unix socket；不可用时回退到 `eve_file`。
    pub eve_socket: Option<PathBuf>,
    /// eve.json 文件（tail 跟踪）。
    pub eve_file: Option<PathBuf>,
    /// severity <= 该值自动封禁（Suricata 1 最高危）。
    pub block_severity_max: u8,
    /// 自动封禁时长（秒）；0 = 永久。
    pub block_seconds: u64,
    /// 规则头预过滤：开启后 XDP 对新建流按 WebAPI 添加的 Suricata 规则头部做
    /// 线速准入，未命中任一规则头部的流直接丢弃（默认关闭，保持现有行为）。
    #[serde(default)]
    pub prefilter: bool,
}

impl Default for Suricata {
    fn default() -> Self {
        Self {
            enabled: true,
            eve_socket: Some(PathBuf::from("/var/run/suricata.sock")),
            eve_file: Some(PathBuf::from("/var/log/suricata/eve.json")),
            block_severity_max: 2,
            block_seconds: 600,
            prefilter: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Multiwan {
    pub enabled: bool,
    /// 探活目标地址（IP）。
    pub probe_host: String,
    /// 探活目标端口。
    pub probe_port: u16,
    /// 探活间隔（秒）。
    pub check_interval_secs: u64,
}

impl Default for Multiwan {
    fn default() -> Self {
        Self {
            enabled: false,
            probe_host: "8.8.8.8".into(),
            probe_port: 53,
            check_interval_secs: 30,
        }
    }
}

/// 连接跟踪配置（每状态超时，秒；0 = 永不过期）。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Conntrack {
    pub enabled: bool,
    /// `CONNTRACK` / `FRAG_TRACK` map 容量。
    pub max_entries: u32,
    /// TCP 已建立（ESTABLISHED）。
    pub tcp_established_secs: u64,
    /// TCP 握手（SYN_SENT / SYN_RECV）。
    pub tcp_handshake_secs: u64,
    /// TCP 关闭（FIN_WAIT / CLOSE_WAIT）。
    pub tcp_closing_secs: u64,
    /// TCP TIME_WAIT / RST。
    pub tcp_time_wait_secs: u64,
    /// UDP。
    pub udp_secs: u64,
    /// ICMP / ICMPv6。
    pub icmp_secs: u64,
    /// 其它协议。
    pub generic_secs: u64,
}

impl Default for Conntrack {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 65536,
            tcp_established_secs: 432000, // 5 天
            tcp_handshake_secs: 120,
            tcp_closing_secs: 120,
            tcp_time_wait_secs: 120,
            udp_secs: 30,
            icmp_secs: 30,
            generic_secs: 600,
        }
    }
}

impl Conntrack {
    /// 按 `CT_STATE_*` 槽位顺序返回超时（秒）。
    pub fn timeouts(&self) -> [u32; k_firewall_common::maps::CT_STATE_MAX] {
        [
            self.tcp_handshake_secs.min(u32::MAX as u64) as u32, // SYN_SENT
            self.tcp_handshake_secs.min(u32::MAX as u64) as u32, // SYN_RECV
            self.tcp_established_secs.min(u32::MAX as u64) as u32,
            self.tcp_closing_secs.min(u32::MAX as u64) as u32, // FIN_WAIT
            self.tcp_closing_secs.min(u32::MAX as u64) as u32, // CLOSE_WAIT
            self.tcp_time_wait_secs.min(u32::MAX as u64) as u32, // TIME_WAIT
            self.udp_secs.min(u32::MAX as u64) as u32,
            self.icmp_secs.min(u32::MAX as u64) as u32,
            self.generic_secs.min(u32::MAX as u64) as u32,
        ]
    }
}

/// IPv6 安全配置。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Ipv6 {
    /// 过滤 ICMPv6 Router Advertisement / Redirect（防路由注入）。
    pub ra_filter: bool,
}

impl Default for Ipv6 {
    fn default() -> Self {
        Self { ra_filter: false }
    }
}

/// QoS 配置。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Qos {
    /// XDP 分类：DSCP 标记 + 每类入口限速（首匹配生效）。
    pub classes: Vec<QosClass>,
}

impl Default for Qos {
    fn default() -> Self {
        Self {
            classes: Vec::new(),
        }
    }
}

/// QoS 分类（XDP）。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct QosClass {
    pub name: String,
    /// 目标 DSCP（0-63）。
    pub dscp: u8,
    /// 入向接口（逻辑名）；None = 任意接口。
    pub ingress_iface: Option<String>,
    /// tcp | udp | icmp | icmp6 | any（默认 any）。
    pub proto: String,
    /// 源端口（0 = 任意）。
    pub src_port: u16,
    /// 目的端口（0 = 任意）。
    pub dst_port: u16,
    /// 每类入口限速（字节/秒）；0 = 不限速。
    pub rate_bps: u64,
    /// 突发字节。
    pub burst_bytes: u32,
}

impl Default for QosClass {
    fn default() -> Self {
        Self {
            name: String::new(),
            dscp: 0,
            ingress_iface: None,
            proto: "any".into(),
            src_port: 0,
            dst_port: 0,
            rate_bps: 0,
            burst_bytes: 16000,
        }
    }
}

impl QosClass {
    fn proto_u8(&self) -> Result<u8> {
        Ok(match self.proto.as_str() {
            "any" => 0,
            "tcp" => 6,
            "udp" => 17,
            "icmp" => 1,
            "icmp6" | "icmpv6" => 58,
            other => bail!("qos class {:?}: unsupported proto {other:?}", self.name),
        })
    }

    fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            bail!("qos class: name is required");
        }
        if self.dscp > 63 {
            bail!("qos class {:?}: dscp out of range 0..63", self.name);
        }
        self.proto_u8()?;
        Ok(())
    }
}

/// 会话日志配置。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SessionLog {
    /// 是否开启会话日志（写入 daemon 日志）。
    pub enabled: bool,
    /// 是否额外转发到 syslog（UDP RFC3164；服务器=127.0.0.1:514）。
    pub syslog_enabled: bool,
    /// syslog 服务器地址。
    pub syslog_server: String,
    /// syslog 服务器端口。
    pub syslog_port: u16,
}

impl Default for SessionLog {
    fn default() -> Self {
        Self {
            enabled: true,
            syslog_enabled: false,
            syslog_server: "127.0.0.1".into(),
            syslog_port: 514,
        }
    }
}

/// 源 IP 速率限制规则：`(src_ip)` -> 令牌桶（`rate` pps，`burst` 突发上限）。
///
/// 命中源 IP 的流量逐包扣令牌，桶空即丢弃。适用于 DDoS / 突发防护。
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitRule {
    /// 源地址（IPv4 或 IPv6）。
    pub src_ip: IpAddr,
    /// 每秒令牌数（pps）。
    pub rate: u32,
    /// 桶容量（允许的突发包数）。
    #[serde(default = "default_burst")]
    pub burst: u32,
}

fn default_burst() -> u32 {
    1000
}

impl RateLimitRule {
    fn validate(&self) -> Result<()> {
        if self.rate == 0 {
            bail!("rate_limit_rules: rate must be > 0");
        }
        if self.burst == 0 {
            bail!("rate_limit_rules: burst must be > 0");
        }
        // eBPF 令牌计算 `elapsed * rate / 1e9` 防溢出：rate 上限约 4 Gpps（u32 最大值内）。
        if self.rate > 4_000_000_000 {
            bail!("rate_limit_rules: rate too large");
        }
        Ok(())
    }
}

/// 每源 IP 并发连接数上限规则：`(src_ip)` -> `max_conns`。
///
/// 该源 IP 建立的新连接数达到上限后丢弃（防止连接表耗尽 / P2P 滥用）。
/// `max_conns = 0` 表示不限制（daemon 不写入 CONN_LIMITS）。
#[derive(Debug, Clone, Deserialize)]
pub struct ConnLimitRule {
    /// 源地址（IPv4 或 IPv6）。
    pub src_ip: IpAddr,
    /// 允许的最大并发连接数。
    pub max_conns: u32,
}

impl ConnLimitRule {
    fn validate(&self) -> Result<()> {
        if self.max_conns == 0 {
            bail!("conn_limits: max_conns must be > 0");
        }
        Ok(())
    }
}

/// SYN Flood 防护全局配置（每源 IP）。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SynFlood {
    /// 每源 IP 新建连接（SYN）速率上限（pps）。0 = 关闭。
    pub rate_pps: u32,
    /// 令牌桶突发容量（允许的瞬间突发 SYN 数）。
    pub burst: u32,
    /// 每源 IP 半开（SYN_SENT/SYN_RECV）连接数上限。0 = 关闭。
    pub max_half_open: u32,
}

impl Default for SynFlood {
    fn default() -> Self {
        Self {
            rate_pps: 0,
            burst: 100,
            max_half_open: 0,
        }
    }
}

impl SynFlood {
    fn validate(&self) -> Result<()> {
        if self.rate_pps > 4_000_000_000 {
            bail!("syn_flood: rate_pps too large");
        }
        if self.burst == 0 && self.rate_pps > 0 {
            bail!("syn_flood: burst must be > 0 when rate_pps enabled");
        }
        Ok(())
    }
}

/// 协议助手（ALG）配置。
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Alg {
    /// FTP ALG：解析端口 21 控制流的 PORT/PASV 应答，学习数据连接。
    pub ftp_enabled: bool,
}

impl Default for Alg {
    fn default() -> Self {
        Self { ftp_enabled: false }
    }
}
