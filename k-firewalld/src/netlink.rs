use std::fs;

use anyhow::Result;
use tracing::info;

/// 枚举本机网络接口（读取 /sys/class/net）。
///
/// 后续里程碑将改用 rtnetlink 0.14 做接口状态/链路管理与 IP 配置。
pub fn log_interfaces() -> Result<()> {
    for entry in fs::read_dir("/sys/class/net")? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        info!("netif {name}");
    }
    Ok(())
}

// TODO(rtnetlink): 接口 up/down、IP 地址配置、路由表管理（多 WAN 策略路由）。
