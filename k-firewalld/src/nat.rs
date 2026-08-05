use anyhow::{Context as _, Result, bail};
use std::process::Command;
use tracing::info;

use k_firewall_common::maps::MODE_ROUTE;

use crate::config::{Config, NAT_MASQUERADE};

/// k-firewalld 专属 NAT 表（仅 IPv4；避免 NAT66 意外覆盖 IPv6 透传语义）。
/// 与宿主机其它 nftables 规则隔离，启动时 flush、退出时 delete，不残留。
const NAT_TABLE: &str = "kfw_nat";

/// IPv6 NAT66 表（`nat6: masquerade` 出口的源地址伪装）。
const NAT6_TABLE: &str = "kfw_nat6";

fn nft(args: &[&str]) -> Result<()> {
    let out = Command::new("nft")
        .args(args)
        .output()
        .context("spawn nft (is nftables installed?)")?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "nft {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

/// 下发/刷新 NAT 规则（声明式）：先清空整个 kfw_nat 表，再按配置注入。
///
/// 仅对 `nat: masquerade` 且 `mode: route` 的接口注入出口伪装规则。
/// `oifname` 出接口匹配天然隔离 LAN↔LAN 跨子网路由（不碰 NAT），
/// 只对发往 WAN 口的流量做源地址伪装。
pub fn sync_nat_rules(config: &Config) -> Result<()> {
    // 幂等：表不存在则创建，存在则整体清空（覆盖上次残留）。
    let add = nft(&["add", "table", "ip", NAT_TABLE]);
    match add {
        Ok(()) => {}
        // "File exists" 属预期；其它错误继续尝试 flush 交由 flush 判断。
        Err(_) => {}
    }
    nft(&["flush", "table", "ip", NAT_TABLE])?;
    nft(&[
        "add",
        "chain",
        "ip",
        NAT_TABLE,
        "postrouting",
        "{",
        "type",
        "nat",
        "hook",
        "postrouting",
        "priority",
        "100",
        ";",
        "policy",
        "accept",
        ";",
        "}",
    ])?;
    nft(&[
        "add",
        "chain",
        "ip",
        NAT_TABLE,
        "prerouting",
        "{",
        "type",
        "nat",
        "hook",
        "prerouting",
        "priority",
        "-100",
        ";",
        "policy",
        "accept",
        ";",
        "}",
    ])?;

    let mut count = 0;
    for ifc in &config.interfaces {
        if ifc.mode_u8()? == MODE_ROUTE && ifc.nat_u8()? == NAT_MASQUERADE {
            let phy = ifc.phy_name();
            nft(&[
                "add",
                "rule",
                "ip",
                NAT_TABLE,
                "postrouting",
                "oifname",
                &phy,
                "masquerade",
            ])?;
            info!("NAT: masquerade on egress {}", phy);
            count += 1;
        }
    }
    for dnat in &config.nat_rules {
        let proto = match dnat.proto.as_str() {
            "tcp" => "tcp",
            "udp" => "udp",
            _ => continue,
        };
        let dst_ip = dnat.dst_ip.to_string();
        let to_ip = dnat.to_ip.to_string();
        let dst_port = dnat.dst_port.to_string();
        let to_port = dnat.to_port.to_string();
        // ip daddr <wan_ip> tcp|udp dport <port> dnat to <server>:<port>
        // `tcp dport` / `udp dport` 已隐含 L4 协议，无需再写 `ip protocol`。
        nft(&[
            "add",
            "rule",
            "ip",
            NAT_TABLE,
            "prerouting",
            "ip",
            "daddr",
            &dst_ip,
            proto,
            "dport",
            &dst_port,
            "dnat",
            "to",
            &format!("{to_ip}:{to_port}"),
        ])?;
        info!("NAT: dnat {}:{dst_port} -> {to_ip}:{to_port}", dst_ip);
        count += 1;
    }
    if count > 0 {
        info!(
            "NAT: synced {} masquerade rule(s) in table {NAT_TABLE}",
            count
        );
    }
    Ok(())
}

/// 退出清理：删除整个 kfw_nat 表（含全部链与规则）。
pub fn cleanup_nat_rules() {
    let _ = nft(&["delete", "table", "ip", NAT_TABLE]);
}

/// 下发/刷新 IPv6 NAT66 规则：对 `nat6: masquerade` 且 `mode: route` 的接口
/// 注入出口源地址伪装规则。独立 `kfw_nat6` 表，与 IPv4 NAT 隔离。
pub fn sync_nat6_rules(config: &Config) -> Result<()> {
    let ifaces = config.nat6_egress_ifaces();
    if ifaces.is_empty() {
        // 无 NAT66 需求时确保旧表被清理（幂等）。
        cleanup_nat6_rules();
        return Ok(());
    }
    let add = nft(&["add", "table", "ip6", NAT6_TABLE]);
    match add {
        Ok(()) => {}
        Err(_) => {}
    }
    nft(&["flush", "table", "ip6", NAT6_TABLE])?;
    nft(&[
        "add",
        "chain",
        "ip6",
        NAT6_TABLE,
        "postrouting",
        "{",
        "type",
        "nat",
        "hook",
        "postrouting",
        "priority",
        "100",
        ";",
        "policy",
        "accept",
        ";",
        "}",
    ])?;

    let mut count = 0;
    for ifc in &config.interfaces {
        if ifc.mode_u8()? == MODE_ROUTE && ifc.nat6_u8()? == NAT_MASQUERADE {
            let phy = ifc.phy_name();
            nft(&[
                "add",
                "rule",
                "ip6",
                NAT6_TABLE,
                "postrouting",
                "oifname",
                &phy,
                "masquerade",
            ])?;
            info!("NAT6: masquerade on egress {}", phy);
            count += 1;
        }
    }
    if count > 0 {
        info!("NAT6: synced {count} masquerade rule(s) in table {NAT6_TABLE}");
    }
    Ok(())
}

/// 退出清理：删除整个 kfw_nat6 表。
pub fn cleanup_nat6_rules() {
    let _ = nft(&["delete", "table", "ip6", NAT6_TABLE]);
}
