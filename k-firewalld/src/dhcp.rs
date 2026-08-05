#![allow(dead_code)]

//! DHCPv6 服务（RFC 8415 最小实现）。
//!
//! 为配置了 `dhcp6_server: <prefix>` 的 LAN 接口提供有状态地址分配：
//! - Solicit（含 Rapid Commit）→ Advertise / Reply
//! - Request / Renew / Rebind → Reply（提交/续租 IA_NA）
//! - Release / Decline → Reply（回收租约）
//! - Information-Request → Reply
//!
//! 每个接口一个 UDP 547 套接字，绑定到具体网卡（SO_BINDTODEVICE）并加入
//! `ff02::1:2` 多播组，只处理本接口流量。地址从配置前缀池按序分配，DUID +
//! IAID 维度维护租约。无第三方依赖（复用 libc / std）。

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Mutex;

use anyhow::{Context as _, Result, anyhow, bail};
use tracing::{debug, info, warn};

use crate::config::Config;

// ---- DHCPv6 消息类型 ----
const SOLICIT: u8 = 1;
const ADVERTISE: u8 = 2;
const REQUEST: u8 = 3;
const CONFIRM: u8 = 4;
const RENEW: u8 = 5;
const REBIND: u8 = 6;
const REPLY: u8 = 7;
const RELEASE: u8 = 8;
const DECLINE: u8 = 9;
const INFORMATION_REQUEST: u8 = 11;

// ---- 常用选项 ----
const O_CLIENTID: u16 = 1;
const O_SERVERID: u16 = 2;
const O_IA_NA: u16 = 3;
const O_IAADDR: u16 = 5;
const O_ORO: u16 = 6;
const O_PREFERENCE: u16 = 7;
const O_ELAPSED: u16 = 8;
const O_STATUS: u16 = 13;
const O_RAPID_COMMIT: u16 = 14;
const O_RECONF_ACCEPT: u16 = 20;

// ---- 状态码 ----
const S_SUCCESS: u16 = 0;
const S_NOLINK: u16 = 2;
const S_NOTONLINK: u16 = 4;

// ---- 生命周期（秒）----
const T1: u32 = 3600;
const T2: u32 = 5400;
const PREFERRED: u32 = 7200;
const VALID: u32 = 86400;

/// DHCPv6 服务器多播地址。
const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// 服务器 DUID（DUID-LL：type=3 + 链路层类型 1 + 接口 MAC）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServerDuid(Vec<u8>);

/// 租约：分配给某个 DUID+IAID 的地址与到期时刻。
struct Lease {
    addr: Ipv6Addr,
    valid_until: std::time::Instant,
}

/// 单个接口的 DHCPv6 服务器状态。
struct IfaceServer {
    /// 逻辑接口名（日志用）。
    name: String,
    /// 物理网卡名。
    phy: String,
    /// ifindex（SO_BINDTODEVICE 用不到，但加入多播组需要）。
    ifindex: u32,
    /// 地址池前缀起始地址（网络地址，主机位清零）。
    pool_base: Ipv6Addr,
    /// 地址池主机位数（前缀 = 128 - 主机位）。
    prefix_len: u8,
    /// 池内主机位可用地址总数（排除 0 与全 1 的 2^(host_bits) - 2）。
    host_count: u64,
    /// DUID + IAID -> 租约。
    leases: Mutex<HashMap<(Vec<u8>, u32), Lease>>,
    /// 下一个分配的池内偏移（尽力避免复用，碰撞则线性探测）。
    next_offset: Mutex<u64>,
    /// 服务器 DUID（由网卡 MAC 派生）。
    server_duid: ServerDuid,
}

pub struct DhcpServer {
    ifaces: Vec<IfaceServer>,
}

/// 计算前缀主机位对应的可用地址数（/64 及以上视为足够大，封顶避免溢出）。
fn host_count(prefix_len: u8) -> u64 {
    let host_bits = 128 - prefix_len;
    if host_bits >= 63 {
        u64::MAX
    } else {
        (1u64 << host_bits) - 2
    }
}

/// 网络序追加 u16 / u32 / 字节。
fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn push_ip(buf: &mut Vec<u8>, a: Ipv6Addr) {
    buf.extend_from_slice(&a.octets());
}

/// 追加一个 DHCPv6 选项（code + len + data）。
fn push_option(buf: &mut Vec<u8>, code: u16, data: &[u8]) {
    push_u16(buf, code);
    push_u16(buf, data.len() as u16);
    buf.extend_from_slice(data);
}

/// 解析 DHCPv6 消息中的选项（返回 (code, data) 列表）。跳过畸形尾部。
fn parse_options(mut data: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while data.len() >= 4 {
        let code = u16::from_be_bytes([data[0], data[1]]);
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        data = &data[4..];
        if len > data.len() {
            break;
        }
        out.push((code, data[..len].to_vec()));
        data = &data[len..];
    }
    out
}

impl ServerDuid {
    /// 从接口 MAC 构造 DUID-LL。
    fn from_mac(name: &str) -> Option<ServerDuid> {
        let text = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
        let mut mac = Vec::new();
        for part in text.trim().split(':') {
            mac.push(u8::from_str_radix(part, 16).ok()?);
        }
        if mac.len() != 6 {
            return None;
        }
        let mut duid = Vec::with_capacity(10);
        push_u16(&mut duid, 3); // DUID-LL
        push_u16(&mut duid, 1); // Ethernet
        duid.extend_from_slice(&mac);
        Some(ServerDuid(duid))
    }
}

impl IfaceServer {
    /// 从池偏移生成 IAADDR（偏移 0 映射到池内第一个可用地址）。
    fn addr_at(&self, offset: u64) -> Ipv6Addr {
        let mut seg = self.pool_base.segments();
        // 把偏移累加到低 64 位（/64 及以上前缀的主机位全在低 64 位）。
        let low = u64::from(seg[6]) << 32 | u64::from(seg[7]);
        let (new_low, _carry) = low.overflowing_add(offset + 1);
        seg[6] = ((new_low >> 32) & 0xFFFF) as u16;
        seg[7] = (new_low & 0xFFFF) as u16;
        Ipv6Addr::from(seg)
    }

    /// 分配一个当前未被占用的池内地址。
    fn alloc_addr(&self, now: std::time::Instant) -> Ipv6Addr {
        self.alloc_addr_locked(&mut self.leases.lock().unwrap(), now)
    }

    /// 分配地址（调用方必须已持有 `leases` 锁，避免 `alloc_for` 二次加锁死锁）。
    fn alloc_addr_locked(&self, guard: &mut HashMap<(Vec<u8>, u32), Lease>, now: std::time::Instant) -> Ipv6Addr {
        let mut offset = *self.next_offset.lock().unwrap();
        // 扫描上限：池远大于实际租约数，碰到已占用就线性探测，最多扫 4096 次。
        let scan_limit = self.host_count.min(4096);
        for _ in 0..scan_limit {
            let addr = self.addr_at(offset % self.host_count);
            let in_use = guard
                .values()
                .any(|l| l.addr == addr && l.valid_until > now);
            if !in_use {
                *self.next_offset.lock().unwrap() = offset + 1;
                return addr;
            }
            offset += 1;
        }
        // 池耗尽：返回 0 地址（客户端将收到 NoAddrsAvail）。
        Ipv6Addr::UNSPECIFIED
    }

    /// 回收（Release / Decline）时移除租约。
    fn release(&self, duid: &[u8], iaid: u32) {
        let mut guard = self.leases.lock().unwrap();
        guard.remove(&(duid.to_vec(), iaid));
    }
}

/// 为配置了 `dhcp6_server` 的接口启动 DHCPv6 服务（每个接口一个任务）。
pub fn spawn_servers(config: &Config) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();
    for ifc in &config.interfaces {
        let Some(pool) = &ifc.dhcp6_server else {
            continue;
        };
        let (pool_base, prefix_len) = match parse_pool(pool) {
            Ok(v) => v,
            Err(e) => {
                warn!("dhcp6_server {:?}: invalid pool: {e:#}", ifc.name);
                continue;
            }
        };
        let ifindex =
            match std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", ifc.phy_name()))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
            {
                Some(i) => i,
                None => {
                    warn!("dhcp6_server {:?}: cannot resolve ifindex", ifc.name);
                    continue;
                }
            };
        let server = IfaceServer {
            name: ifc.name.clone(),
            phy: ifc.phy_name(),
            ifindex,
            pool_base,
            prefix_len,
            host_count: host_count(prefix_len),
            leases: Mutex::new(HashMap::new()),
            next_offset: Mutex::new(0),
            server_duid: match ServerDuid::from_mac(&ifc.phy_name()) {
                Some(d) => d,
                None => {
                    warn!("dhcp6_server {:?}: no MAC for {}", ifc.name, ifc.phy_name());
                    continue;
                }
            },
        };
        info!(
            "DHCPv6: serving {}/{} on {} ({})",
            pool_base,
            prefix_len,
            ifc.name,
            ifc.phy_name()
        );
        handles.push(tokio::spawn(run_server(server)));
    }
    handles
}

fn parse_pool(pool: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr, pfx) = pool
        .split_once('/')
        .ok_or_else(|| anyhow!("expected prefix/CIDR"))?;
    let addr: Ipv6Addr = addr.parse().context("invalid IPv6 address")?;
    let pfx: u8 = pfx.parse().context("invalid prefix length")?;
    if pfx > 64 {
        bail!("prefix length {pfx} too small (max /64)");
    }
    // 主机位清零。
    let octets = addr.octets();
    let mut out = [0u8; 16];
    for i in 0..16 {
        let bits_consumed = i as u8 * 8;
        let remaining = pfx.saturating_sub(bits_consumed);
        if remaining >= 8 {
            out[i] = octets[i];
        } else if remaining > 0 {
            out[i] = octets[i] & (0xFF << (8 - remaining));
        }
    }
    Ok((Ipv6Addr::from(out), pfx))
}

async fn run_server(server: IfaceServer) {
    let sock = match bind_iface_socket(&server) {
        Ok(s) => s,
        Err(e) => {
            warn!("DHCPv6 {:?}: bind failed: {e:#}", server.name);
            return;
        }
    };
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("DHCPv6 {:?}: recv error: {e}", server.name);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        match handle_message(&server, &buf[..n]) {
            Ok(Some(resp)) => {
                // 响应发回客户端源地址（Solicit/Request 等）。
                let _ = sock.send_to(&resp, peer).await;
            }
            Ok(None) => {}
            Err(e) => debug!("DHCPv6 {:?}: {}: {e}", server.name, server.name),
        }
    }
}

/// 创建绑定到指定网卡的 UDP 547 套接字并加入多播组。
fn bind_iface_socket(server: &IfaceServer) -> Result<tokio::net::UdpSocket> {
    // 多接口同时监听 547：所有套接字必须先开 SO_REUSEADDR + SO_REUSEPORT，
    // 否则第二个接口的 bind([::]:547) 会因地址占用失败。内核按
    // SO_BINDTODEVICE 过滤，保证各套接字只收到本接口流量。
    // 选项必须在 bind 前设置，因此用 libc 原生创建 socket。
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        bail!("socket(AF_INET6): {}", std::io::Error::last_os_error());
    }
    for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
        let on: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            warn!(
                "DHCPv6 {:?}: setsockopt({opt}) failed: {}",
                server.name,
                std::io::Error::last_os_error()
            );
        }
    }
    // IPV6_V6ONLY：只收 IPv6（多播/双栈只监 IPv6，避免占用 IPv4 547）。
    let on: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        warn!(
            "DHCPv6 {:?}: IPV6_V6ONLY failed: {}",
            server.name,
            std::io::Error::last_os_error()
        );
    }
    // bind [::]:547。
    let addr6 = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 547u16.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
        sin6_scope_id: 0,
    };
    let ret = unsafe {
        libc::bind(
            fd,
            (&addr6 as *const libc::sockaddr_in6).cast(),
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        bail!("bind [::]:547: {}", std::io::Error::last_os_error());
    }
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    sock.join_multicast_v6(&ALL_DHCP_RELAY_AGENTS_AND_SERVERS, server.ifindex)?;
    sock.set_multicast_loop_v6(false)?;
    // IPV6_MULTICAST_HOPS：std 无 set_multicast_hops_v6，用 libc。
    let hops: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            (&hops as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        warn!(
            "DHCPv6 {:?}: IPV6_MULTICAST_HOPS failed: {}",
            server.name,
            std::io::Error::last_os_error()
        );
    }

    // SO_BINDTODEVICE：只收本接口包（多接口同时监听时互不串扰）。
    let ifname = std::ffi::CString::new(server.phy.as_str())?;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            ifname.as_ptr().cast(),
            ifname.as_bytes().len() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let e = std::io::Error::last_os_error();
        warn!(
            "DHCPv6 {:?}: SO_BINDTODEVICE({}) failed: {e}",
            server.name, server.phy
        );
    }

    Ok(tokio::net::UdpSocket::from_std(sock)?)
}

/// 处理单个 DHCPv6 消息，返回可选的响应报文。
fn handle_message(server: &IfaceServer, data: &[u8]) -> Result<Option<Vec<u8>>> {
    if data.len() < 4 {
        return Ok(None);
    }
    let msg_type = data[0];
    let txid = [data[1], data[2], data[3]];
    let options = parse_options(&data[4..]);

    // 客户端 DUID 是几乎所有响应都必须回显的。
    let client_duid = match options.iter().find(|(c, _)| *c == O_CLIENTID) {
        Some((_, d)) => d.clone(),
        None => return Ok(None), // 无 ClientID 忽略。
    };
    let client_duid_bytes = client_duid.clone();

    // IA_NA 请求（可从外层或 IAADDR 内解析）。只处理第一个 IA_NA。
    let ia_na = options.iter().find(|(c, _)| *c == O_IA_NA).cloned();
    let iaid = match &ia_na {
        Some((_, d)) if d.len() >= 4 => u32::from_be_bytes([d[0], d[1], d[2], d[3]]),
        _ => 0,
    };

    // 请求的 IAADDR（若有，用于续租校验）。IA_NA 载荷 <12 字节时不解析内嵌 IAADDR。
    let requested_addr = ia_na.as_ref().and_then(|(_, d)| {
        if d.len() < 12 {
            return None;
        }
        // IA_NA 内嵌 IAADDR：跳过 IAID(4)+T1(4)+T2(4)。
        parse_options(&d[12..])
            .iter()
            .find(|(c, _)| *c == O_IAADDR)
            .map(|(_, a)| {
                if a.len() >= 16 {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&a[..16]);
                    Ipv6Addr::from(o)
                } else {
                    Ipv6Addr::UNSPECIFIED
                }
            })
    });

    let mut resp = Vec::new();
    match msg_type {
        SOLICIT => {
            let rapid = options.iter().any(|(c, _)| *c == O_RAPID_COMMIT);
            // Advertise（无快速提交）或 Reply（快速提交）。
            resp.push(if rapid { REPLY } else { ADVERTISE });
            resp.extend_from_slice(&txid);
            push_option(&mut resp, O_SERVERID, &server.server_duid.0);
            push_option(&mut resp, O_CLIENTID, &client_duid);
            if rapid {
                push_option(&mut resp, O_RAPID_COMMIT, &[]);
            }
            if iaid != 0 {
                let addr = alloc_for(&server, &client_duid_bytes, iaid);
                push_ia_na(&mut resp, iaid, addr);
            } else {
                push_option(&mut resp, O_STATUS, &status_code(S_NOTONLINK, "no IA_NA"));
            }
        }
        REQUEST | RENEW | REBIND => {
            resp.push(REPLY);
            resp.extend_from_slice(&txid);
            push_option(&mut resp, O_SERVERID, &server.server_duid.0);
            push_option(&mut resp, O_CLIENTID, &client_duid);
            if iaid == 0 {
                push_option(&mut resp, O_STATUS, &status_code(S_NOTONLINK, "no IA_NA"));
            } else {
                // 续租：客户端在配置地址上；若非本池地址返回 NotOnLink。
                if let Some(req) = requested_addr {
                    if req != Ipv6Addr::UNSPECIFIED && !in_pool(server, req) {
                        push_ia_na_status(&mut resp, iaid, S_NOTONLINK);
                    } else {
                        let addr = alloc_for(&server, &client_duid_bytes, iaid);
                        push_ia_na(&mut resp, iaid, addr);
                    }
                } else {
                    let addr = alloc_for(&server, &client_duid_bytes, iaid);
                    push_ia_na(&mut resp, iaid, addr);
                }
            }
        }
        RELEASE => {
            resp.push(REPLY);
            resp.extend_from_slice(&txid);
            push_option(&mut resp, O_SERVERID, &server.server_duid.0);
            push_option(&mut resp, O_CLIENTID, &client_duid);
            if iaid != 0 {
                server.release(&client_duid_bytes, iaid);
            }
            push_option(&mut resp, O_STATUS, &status_code(S_SUCCESS, "released"));
        }
        DECLINE => {
            resp.push(REPLY);
            resp.extend_from_slice(&txid);
            push_option(&mut resp, O_SERVERID, &server.server_duid.0);
            push_option(&mut resp, O_CLIENTID, &client_duid);
            if iaid != 0 {
                server.release(&client_duid_bytes, iaid);
            }
            push_option(&mut resp, O_STATUS, &status_code(S_SUCCESS, "declined"));
        }
        INFORMATION_REQUEST => {
            resp.push(REPLY);
            resp.extend_from_slice(&txid);
            push_option(&mut resp, O_SERVERID, &server.server_duid.0);
            push_option(&mut resp, O_CLIENTID, &client_duid);
        }
        _ => return Ok(None),
    }
    Ok(Some(resp))
}

fn status_code(code: u16, msg: &str) -> Vec<u8> {
    let mut v = Vec::new();
    push_u16(&mut v, code);
    v.extend_from_slice(msg.as_bytes());
    v
}

fn push_ia_na(resp: &mut Vec<u8>, iaid: u32, addr: Ipv6Addr) {
    let mut ia = Vec::new();
    push_u32(&mut ia, iaid);
    push_u32(&mut ia, T1);
    push_u32(&mut ia, T2);
    let mut iaaddr = Vec::new();
    push_ip(&mut iaaddr, addr);
    push_u32(&mut iaaddr, PREFERRED);
    push_u32(&mut iaaddr, VALID);
    push_option(&mut ia, O_IAADDR, &iaaddr);
    push_option(resp, O_IA_NA, &ia);
}

fn push_ia_na_status(resp: &mut Vec<u8>, iaid: u32, code: u16) {
    let mut ia = Vec::new();
    push_u32(&mut ia, iaid);
    push_u32(&mut ia, T1);
    push_u32(&mut ia, T2);
    push_option(&mut ia, O_STATUS, &status_code(code, "NotOnLink"));
    push_option(resp, O_IA_NA, &ia);
}

fn in_pool(server: &IfaceServer, addr: Ipv6Addr) -> bool {
    let base = server.pool_base.octets();
    let a = addr.octets();
    let pfx = server.prefix_len;
    for i in 0..16 {
        let bits_consumed = i as u8 * 8;
        let remaining = pfx.saturating_sub(bits_consumed);
        if remaining >= 8 {
            if base[i] != a[i] {
                return false;
            }
        } else if remaining > 0 {
            let mask = 0xFF << (8 - remaining);
            if base[i] & mask != a[i] & mask {
                return false;
            }
        }
    }
    true
}

/// 分配（或复用已有）租约地址。池耗尽时返回 0 地址。
fn alloc_for(server: &IfaceServer, duid: &[u8], iaid: u32) -> Ipv6Addr {
    let now = std::time::Instant::now();
    let mut guard = server.leases.lock().unwrap();
    // 惰性清理过期租约（每次分配最多扫描清 16 条，防止长尾客户端占用内存）。
    prune_expired_locked(&mut guard, now, 16);
    if let Some(l) = guard.get(&(duid.to_vec(), iaid)) {
        if l.valid_until > now {
            return l.addr;
        }
        guard.remove(&(duid.to_vec(), iaid));
    }
    let addr = server.alloc_addr_locked(&mut guard, now);
    if addr == Ipv6Addr::UNSPECIFIED {
        return addr;
    }
    guard.insert(
        (duid.to_vec(), iaid),
        Lease {
            addr,
            valid_until: now + std::time::Duration::from_secs(VALID as u64),
        },
    );
    addr
}

/// 从租约表中移除已过期的条目（最多清理 `limit` 条，限制单次遍历开销）。
fn prune_expired_locked(
    leases: &mut std::sync::MutexGuard<'_, HashMap<(Vec<u8>, u32), Lease>>,
    now: std::time::Instant,
    limit: usize,
) {
    let mut expired: Vec<(Vec<u8>, u32)> = Vec::new();
    for (k, l) in leases.iter() {
        if l.valid_until <= now {
            expired.push(k.clone());
            if expired.len() >= limit {
                break;
            }
        }
    }
    for k in expired {
        leases.remove(&k);
    }
}
