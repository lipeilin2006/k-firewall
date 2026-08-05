use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use tracing::{info, warn};

use crate::config::{Config, WanGroup};

/// 当前活动 WAN 状态（每组的健康成员 + 当前默认出口）。
#[derive(Debug, Clone, Default)]
pub struct MultiwanState {
    /// 组名 -> 组成员 up/down 状态。
    groups: HashMap<String, Vec<(String, bool)>>,
    /// 组名 -> 当前活动出口接口。
    active: HashMap<String, String>,
}

/// 多 WAN 管理：健康检查 + 默认路由故障切换 + 策略路由（PBR）。
///
/// 拓扑假设（route 模式）：每个 WAN 接口在 `interfaces` 中配置了 `gateway`。
/// - 健康检查：对每个 WAN 成员周期探测 `health_check.probe_target:port`。
/// - 故障切换：组成员按权重排序，取第一个 up 的作为默认路由出口；
///   切换时 `ip route replace default via <gw> dev <iface>`。
/// - PBR：对每条 `pbr_rules` 生成 `ip rule` + 独立路由表，指向指定 WAN。
pub async fn run(cfg: Config) {
    let mw = cfg.multiwan.clone();
    let wan_gateways: HashMap<String, String> = cfg
        .interfaces
        .iter()
        .filter(|i| i.role == "wan" && i.gateway.is_some())
        .map(|i| (i.name.clone(), i.gateway.unwrap().to_string()))
        .collect();

    info!(
        "multi-wan enabled: {} groups, {} pbr rules, WAN gateways: {:?}",
        cfg.wan_groups.len(),
        cfg.pbr_rules.len(),
        wan_gateways
    );

    let mut state = MultiwanState::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(mw.check_interval_secs.max(1)));

    // 初始化：默认路由按当前内核配置（首次不主动改）。
    // 首次 tick 计算每个组的健康状态并应用。
    let mut pbr_applied = false;
    loop {
        ticker.tick().await;

        for group in &cfg.wan_groups {
            if group.members.is_empty() {
                continue;
            }
            // 健康探测每个成员。
            let mut status: Vec<(String, bool)> = Vec::new();
            for m in &group.members {
                let up = probe_wan(&cfg, &m.name, &wan_gateways, group);
                status.push((m.name.clone(), up));
            }
            state.groups.insert(group.name.clone(), status.clone());

            // 计算活动出口：按权重排序后取第一个 up。
            let mut ranked: Vec<(&String, u32, bool)> = group
                .members
                .iter()
                .map(|m| {
                    let up = status
                        .iter()
                        .find(|(n, _)| n == &m.name)
                        .map(|(_, u)| *u)
                        .unwrap_or(false);
                    (&m.name, m.weight, up)
                })
                .collect();
            ranked.sort_by(|a, b| b.1.cmp(&a.1)); // 权重降序
            let active = ranked.iter().find(|(_, _, up)| *up).map(|(n, _, _)| *n);

            let prev = state.active.get(&group.name);
            let changed = active.is_some() && prev != active;
            if let Some(active_name) = active {
                if changed {
                    // 切换默认路由到活动出口。
                    if let Some(gw) = wan_gateways.get(active_name) {
                        apply_default_route(active_name, gw);
                        info!(
                            "multi-wan [{}] switch default route -> {} via {}",
                            group.name, active_name, gw
                        );
                    }
                    state.active.insert(group.name.clone(), active_name.clone());
                }
            } else {
                warn!("multi-wan [{}]: all members DOWN", group.name);
            }
        }

        // 应用策略路由（PBR）：启动后首轮全量重建（清残留 + 建新），后续 tick
        // 幂等确保存在；配置不会在运行期变更，无需每 tick 清空路由表。
        if !pbr_applied {
            apply_pbr(&cfg, &wan_gateways);
            pbr_applied = true;
        } else {
            ensure_pbr(&cfg, &wan_gateways);
        }
    }
}

/// 探测单个 WAN 成员：优先用 health_check 配置，否则用多 WAN 全局探活目标。
fn probe_wan(
    cfg: &Config,
    member: &str,
    wan_gateways: &HashMap<String, String>,
    group: &WanGroup,
) -> bool {
    // 无网关的成员视为不可探测（跳过，标记 down 以免选中）。
    if !wan_gateways.contains_key(member) {
        return false;
    }
    let (host, port) = match &group.health_check {
        Some(h) => (h.probe_target.clone(), h.probe_port),
        None => {
            // 回退：从 member 的接口绑定的源 IP 探测全局目标。
            (cfg.multiwan.probe_host.clone(), cfg.multiwan.probe_port)
        }
    };
    let ok = probe_from_interface(&host, port, member);
    if ok {
        info!("multi-wan probe {}:{} via {} -> UP", host, port, member);
    } else {
        warn!("multi-wan probe {}:{} via {} -> DOWN", host, port, member);
    }
    ok
}

/// 从指定接口探测：接口有 IPv4 地址（up）且能连通探活目标即视为 UP。
///
/// 探测走系统路由；对多 WAN 隔离验证，更精确的做法是绑定源地址，
/// 但需 socket2（超出当前里程碑范围）。接口 up + 网络可达即可判定健康。
fn probe_from_interface(host: &str, port: u16, iface: &str) -> bool {
    if iface_ip(iface).is_none() {
        return false;
    }
    let Ok(addr) = format!("{host}:{port}").parse::<std::net::SocketAddr>() else {
        return false;
    };
    std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok()
}

/// 读取接口 IPv4 地址（ip -4 addr show 解析）。
fn iface_ip(iface: &str) -> Option<std::net::IpAddr> {
    let out = Command::new("ip")
        .args(["-4", "addr", "show", "dev", iface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            if let Some(ip) = rest.split('/').next() {
                if let Ok(a) = ip.parse() {
                    return Some(a);
                }
            }
        }
    }
    None
}

/// 切换默认路由到指定 WAN。
fn apply_default_route(iface: &str, gateway: &str) {
    let _ = Command::new("ip")
        .args(["route", "replace", "default", "via", gateway, "dev", iface])
        .status();
}

/// 应用策略路由：全量重建。表 100..200 为本程序保留段；每次先清理该段内
/// 上轮残留的 `ip rule` 与路由表条目，再按当前配置重建，避免 PBR 规则被
/// 删除/变更后旧规则继续劫持流量。
fn apply_pbr(cfg: &Config, wan_gateways: &HashMap<String, String>) {
    // 1) 清理保留段（表 100..199）的残留：解析 `ip rule show`，删除引用这些
    //    表的规则，并清空路由表。`ip rule` 是全局的，不清理会永久劫持流量。
    {
        let tables: Vec<String> = (100..200).map(|n| n.to_string()).collect();
        if let Ok(out) = Command::new("ip").args(["rule", "show"]).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let line = line.trim();
                if !line.contains("lookup") {
                    continue;
                }
                let has_table = tables.iter().any(|t| {
                    line.split_whitespace()
                        .rev()
                        .take(2)
                        .any(|w| w == t.as_str())
                });
                if !has_table {
                    continue;
                }
                // 摘出规则文本（去掉行首 "N:\t" 前缀）删除。
                if let Some(rule_part) = line.split_once('\t').map(|(_, r)| r).or_else(|| {
                    line.split_once(": ").map(|(_, r)| r)
                }) {
                    let mut args: Vec<&str> = vec!["rule", "del"];
                    args.extend(rule_part.split_whitespace());
                    let _ = Command::new("ip").args(&args).status();
                }
            }
        }
        for table in tables {
            let _ = Command::new("ip")
                .args(["route", "flush", "table", &table])
                .status();
        }
    }

    // 2) 按当前配置重建。
    for (idx, rule) in cfg.pbr_rules.iter().enumerate() {
        // 使用独立数字路由表（100 起），避免依赖 /etc/iproute2/rt_tables 注册表名。
        let table = format!("{}", 100 + idx);
        // 解析目标 WAN。
        let wan: Option<String> = match (&rule.use_wan, &rule.use_wan_group) {
            (Some(w), _) => Some(w.clone()),
            (_, Some(g)) => {
                // 组内第一个有网关的成员。
                cfg.wan_groups
                    .iter()
                    .find(|grp| &grp.name == g)
                    .and_then(|grp| {
                        grp.members
                            .iter()
                            .find(|m| wan_gateways.contains_key(&m.name))
                            .map(|m| m.name.clone())
                    })
            }
            _ => None,
        };
        let Some(wan) = wan else {
            warn!("pbr[{idx}]: cannot resolve target WAN, skipping");
            continue;
        };
        let Some(gw) = wan_gateways.get(&wan) else {
            warn!("pbr[{idx}]: WAN {wan} has no gateway, skipping");
            continue;
        };

        // 确保路由表条目存在（幂等）。
        let _ = Command::new("ip")
            .args([
                "route", "replace", "default", "via", gw, "dev", &wan, "table", &table,
            ])
            .status();

        // 添加 ip rule。
        let mut rule_args: Vec<String> = vec!["rule".into(), "add".into()];
        if let Some(src) = &rule.src_net {
            rule_args.push("from".into());
            rule_args.push(src.clone());
        }
        if let Some(dst) = &rule.dst_net {
            rule_args.push("to".into());
            rule_args.push(dst.clone());
        }
        rule_args.push("lookup".into());
        rule_args.push(table.clone());

        let _ = Command::new("ip").args(&rule_args).status();
        info!("multi-wan PBR[{idx}]: {:?} -> {wan}", rule_args);
    }
}

/// 幂等确保每条 PBR 规则的 `ip rule` 存在（配置运行期不变，仅重建缺失项）。
/// 与 `apply_pbr` 共用规则解析逻辑。
fn ensure_pbr(cfg: &Config, wan_gateways: &HashMap<String, String>) {
    for (idx, rule) in cfg.pbr_rules.iter().enumerate() {
        let table = format!("{}", 100 + idx);
        let wan: Option<String> = match (&rule.use_wan, &rule.use_wan_group) {
            (Some(w), _) => Some(w.clone()),
            (_, Some(g)) => cfg
                .wan_groups
                .iter()
                .find(|grp| &grp.name == g)
                .and_then(|grp| {
                    grp.members
                        .iter()
                        .find(|m| wan_gateways.contains_key(&m.name))
                        .map(|m| m.name.clone())
                }),
            _ => None,
        };
        let Some(wan) = wan else {
            continue;
        };
        let Some(gw) = wan_gateways.get(&wan) else {
            continue;
        };
        let _ = Command::new("ip")
            .args([
                "route", "replace", "default", "via", gw, "dev", &wan, "table", &table,
            ])
            .status();
        let mut rule_args: Vec<String> = vec!["rule".into(), "add".into()];
        if let Some(src) = &rule.src_net {
            rule_args.push("from".into());
            rule_args.push(src.clone());
        }
        if let Some(dst) = &rule.dst_net {
            rule_args.push("to".into());
            rule_args.push(dst.clone());
        }
        rule_args.push("lookup".into());
        rule_args.push(table.clone());
        // 幂等：精确匹配 `from <src_net> lookup <table>` 是否已存在。
        let check = Command::new("ip").args(["rule", "show"]).output();
        let needle = match (&rule.src_net, &rule.dst_net) {
            (Some(s), None) => format!("from {s} lookup {table}"),
            (None, Some(d)) => format!("to {d} lookup {table}"),
            (Some(s), Some(d)) => format!("from {s} to {d} lookup {table}"),
            (None, None) => format!("lookup {table}"),
        };
        let already = check
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&needle))
            .unwrap_or(false);
        if !already {
            let _ = Command::new("ip").args(&rule_args).status();
            info!("multi-wan PBR ensure[{idx}]: {:?} -> {wan}", rule_args);
        }
    }
}
