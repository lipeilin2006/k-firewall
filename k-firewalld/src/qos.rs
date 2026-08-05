//! QoS 出口整形（HTB）。
//!
//! XDP 入口已按 `qos.classes` 对匹配包打 DSCP（`mark_ipv4_dscp` / `mark_ipv6_dscp`）。
//! 此处为 `qos.shaping` 配置在出口物理网卡下发 HTB：
//! - 根 qdisc：`htb default <default_classid minor>`
//! - 每个 `QosShapingClass`：一个 `1:xx` class，按 DSCP 的 u32 过滤匹配
//!   IPv4（`match ip tos`）与 IPv6（`match ip6 priority`）后进入对应 class。
//!
//! 与连接跟踪 / 规则检测独立：DSCP 标记只改 ToS/Traffic Class 与校验和，不改
//! 五元组，因此不会破坏 eBPF 的匹配。

use std::process::Command;

use anyhow::{Context as _, Result, bail};
use tracing::{info, warn};

use crate::config::Config;

fn tc(args: &[&str]) -> Result<()> {
    let out = Command::new("tc")
        .args(args)
        .output()
        .context("spawn tc (is iproute2 installed?)")?;
    if out.status.success() {
        Ok(())
    } else {
        // `RTNETLINK answers: File exists` 等表示已存在，可忽略；其余报错。
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if stderr.contains("File exists") || stderr.contains("No such file or directory") {
            return Ok(());
        }
        bail!("tc {} failed: {stderr}", args.join(" "))
    }
}

/// 解析 classid 的小号（default 参数只用 minor 十进制）。如 `1:10` -> `10`。
fn class_minor(classid: &str) -> Result<u32> {
    let minor = classid.split_once(':').map(|(_, m)| m).unwrap_or(classid);
    let minor = minor.trim();
    let minor = if let Some(hex) = minor.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).with_context(|| format!("bad classid {classid:?}"))?
    } else {
        minor
            .parse::<u32>()
            .with_context(|| format!("bad classid {classid:?}"))?
    };
    if minor == 0 {
        bail!("classid {classid:?}: minor must be nonzero");
    }
    Ok(minor)
}

/// 按 `qos.shaping` 声明式下发 HTB 规则。
///
/// 幂等：先删除物理网卡 root qdisc（忽略不存在），再重建。同接口配置变更后
/// 重启 daemon 即可整体重下。
pub fn setup_shaping(config: &Config) -> Result<()> {
    for s in &config.qos.shaping {
        let phy = match config.interfaces.iter().find(|i| &i.name == &s.interface) {
            Some(ifc) => ifc.phy_name(),
            None => {
                warn!(
                    "qos.shaping: interface {:?} not found, skipped",
                    s.interface
                );
                continue;
            }
        };
        apply_shaping(&phy, s)?;
    }
    Ok(())
}

fn apply_shaping(phy: &str, s: &crate::config::QosShaping) -> Result<()> {
    // 先清理旧 qdisc（不存在时报 "No such file or directory"，tc() 忽略）。
    let _ = tc(&["qdisc", "del", "dev", phy, "root"]);

    let default_minor = class_minor(&s.default_classid)?;
    tc(&[
        "qdisc",
        "add",
        "dev",
        phy,
        "root",
        "handle",
        "1:",
        "htb",
        "default",
        &default_minor.to_string(),
    ])
    .with_context(|| format!("add htb root qdisc on {phy}"))?;
    info!("QoS: htb root on {phy} default {}", s.default_classid);

    let mut has_class = false;
    for c in &s.classes {
        let minor = class_minor(&c.classid)?;
        // rate/ceil 配置为字节/秒，tc 接受裸数值（bps）与后缀，这里显式用 bit 单位。
        let rate_bits = c.rate_bps.saturating_mul(8);
        let ceil_bits = if c.ceil_bps == 0 {
            c.rate_bps
        } else {
            c.ceil_bps
        }
        .saturating_mul(8);
        let burst = c.burst_bytes.max(1);
        tc(&[
            "class",
            "add",
            "dev",
            phy,
            "parent",
            "1:",
            "classid",
            &c.classid,
            "htb",
            "rate",
            &rate_bits.to_string(),
            "ceil",
            &ceil_bits.to_string(),
            "burst",
            &burst.to_string(),
        ])
        .with_context(|| format!("add htb class {} on {phy}", c.classid))?;

        // 按 DSCP 匹配（保留 ECN 位，掩码 0xfc）：IPv4 TOS / IPv6 Traffic Class。
        let tos_value = (c.dscp as u32) << 2;
        let tos_hex = format!("0x{tos_value:x}");
        tc(&[
            "filter", "add", "dev", phy, "parent", "1:", "protocol", "ip", "prio", "1", "u32",
            "match", "ip", "tos", &tos_hex, "0xfc", "flowid", &c.classid,
        ])
        .with_context(|| format!("add ipv4 dscp filter {} on {phy}", c.classid))?;
        tc(&[
            "filter", "add", "dev", phy, "parent", "1:", "protocol", "ipv6", "prio", "1", "u32",
            "match", "ip6", "priority", &tos_hex, "0xfc", "flowid", &c.classid,
        ])
        .with_context(|| format!("add ipv6 dscp filter {} on {phy}", c.classid))?;

        info!(
            "QoS: {} class {} dscp {} rate {}bps ceil {}bps",
            phy, c.classid, c.dscp, rate_bits, ceil_bits
        );
        has_class = true;
    }

    if !has_class {
        warn!("QoS: no classes configured for {phy}, only default class applied");
    }
    Ok(())
}
