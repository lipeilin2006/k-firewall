use anyhow::{Context as _, Result, bail};
use std::collections::HashSet;
use std::process::Command;
use tracing::info;

use k_firewall_common::maps::{MODE_HYBRID, MODE_TRANSPARENT};

use crate::config::Config;

/// 为带 peer 的透明/混合接口对创建 Linux bridge 并加入两端物理接口。
///
/// 透明模式的 L2 转发（ARP 泛洪、MAC 学习、未知单播转发）由内核 bridge
/// 完成，XDP 程序只做规则检测，检测通过后 XDP_PASS 交给 bridge。
pub fn setup_transparent_bridges(config: &Config) -> Result<()> {
    // 找出所有 transparent/hybrid 接口，按 (自身, peer) 配对。
    let mut paired = HashSet::new();
    for ifc in &config.interfaces {
        let mode = ifc.mode_u8()?;
        if mode != MODE_TRANSPARENT && mode != MODE_HYBRID {
            continue;
        }
        let Some(peer_name) = &ifc.peer else {
            bail!("interface {} mode requires peer", ifc.name);
        };
        // 避免重复处理同一对（lan2 看到 wan2，wan2 又看到 lan2）。
        let pair_key = if ifc.name < *peer_name {
            format!("{}-{}", ifc.name, peer_name)
        } else {
            format!("{}-{}", peer_name, ifc.name)
        };
        if !paired.insert(pair_key.clone()) {
            continue;
        }
        let phy_a = ifc.phy_name();
        let peer = config
            .interfaces
            .iter()
            .find(|o| &o.name == peer_name)
            .context("peer interface not found")?;
        let phy_b = peer.phy_name();
        // 一个 bridge 承载一组透明对。注意：bridge 名不能含连字符
        // （ip link add type bridge 对该字符报 policy validation 失败）。
        let br_name = format!("kfwbr_{}", &pair_key.replace('-', "_"));
        ensure_bridge(&br_name)?;
        enslave(&br_name, &phy_a)?;
        enslave(&br_name, &phy_b)?;
        info!(
            "transparent pair {}<->{} on bridge {}",
            phy_a, phy_b, br_name
        );
    }
    Ok(())
}

fn run(args: &[&str]) -> Result<()> {
    let out = Command::new("ip").args(args).output().context("spawn ip")?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

fn ensure_bridge(name: &str) -> Result<()> {
    // 已存在则直接返回（幂等）。
    if std::path::Path::new(&format!("/sys/class/net/{name}")).exists() {
        return Ok(());
    }
    run(&["link", "add", name, "type", "bridge"])?;
    run(&["link", "set", "dev", name, "up"])?;
    Ok(())
}

fn enslave(br: &str, iface: &str) -> Result<()> {
    run(&["link", "set", "dev", iface, "down"])?;
    run(&["link", "set", "dev", iface, "master", br])?;
    run(&["link", "set", "dev", iface, "up"])?;
    Ok(())
}
