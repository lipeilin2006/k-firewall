use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    if cfg!(not(target_os = "linux")) {
        // eBPF 只在 Linux 上构建；Windows/macOS 上跳过。
        println!("cargo:warning=skipping eBPF build on non-Linux host");
        return Ok(());
    }

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "k-firewall-ebpf")
        .ok_or_else(|| anyhow!("k-firewall-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
