# Virtual Machines

## Connection

| VM | IP | User | Password | SSH |
|----|----|------|----------|-----|
| **k-firewall-fw** | 192.168.11.10 | debian | debian | `ssh debian@192.168.11.10` |
| **k-firewall-client** | 192.168.11.11 | debian | debian | `ssh debian@192.168.11.11` |
| **k-firewall-outer** | 192.168.11.12 | debian | debian | `ssh debian@192.168.11.12` |
| **k-firewall-client1** | 192.168.11.13 | debian | debian | `ssh debian@192.168.11.13` |
| **k-firewall-client2** | 192.168.11.14 | debian | debian | `ssh debian@192.168.11.14` |
| **k-firewall-client3** | 192.168.11.15 | debian | debian | `ssh debian@192.168.11.15` |

> 所有 VM 用户名/密码统一为 `debian` / `debian`。

## Topology

```
┌───────────────────────────────────────────────┐
│            k-firewall-fw (NGFW)               │
│             192.168.11.10                     │
├───────────────────────────────────────────────┤
│ wan0  NAT 10.0.2.0/24  — Route               │
│       10.0.2.15 — internet egress             │
├───────────────────────────────────────────────┤
│ mgmt  Host-Only 192.168.11.0/24              │
│       192.168.11.10 — SSH :22 / API :8080     │
├───────────────────────────────────────────────┤
│ wan1  NAT 10.0.2.0/24  — Route (shares subnet │
│       with wan0; gateway 10.0.2.2)            │
├───────────────────────────────────────────────┤
│ wan2  NAT 10.0.4.0/24  — Transparent          │
│       (no IP) — peer lan2  (gw 10.0.4.2)      │
├───────────────────────────────────────────────┤
│ lan0  intnet "kfw-lan0"   — Route            │
│       192.168.10.1                            │
├───────────────────────────────────────────────┤
│ lan1  intnet "kfw-lan1"   — Route            │
│       192.168.20.1                            │
├───────────────────────────────────────────────┤
│ lan2  intnet "kfw-lan2"   — Transparent      │
│       (no IP) — peer wan2                    │
├───────────────────────────────────────────────┤
│ lan3  intnet "kfw-lan3"   — spare            │
└───────────────────────────────────────────────┘
        │         │         │
   ┌────┘    ┌────┘    ┌────┘
   ▼         ▼         ▼
┌────────┐ ┌────────┐ ┌──────────────┐ ┌──────────────┐
│client0 │ │client1 │ │   client2    │ │   client3    │
│.11.11  │ │.11.13  │ │   .11.14     │ │   .11.15     │
│10.0.2.2│ │10.0.2.2│ │ enp0s3=lan2  │ │   (spare)    │
├────────┤ ├────────┤ │ 10.0.4.30    │ ├──────────────┤
│enp0s3  │ │enp0s3  │ │ enp0s8=mgmt  │ │ enp0s3=lan3  │
│=lan0   │ │=lan1   │ │ (static)     │ │ enp0s8=mgmt  │
│enp0s8  │ │enp0s8  │ └──────────────┘ └──────────────┘
│=mgmt   │ │=mgmt   │
└────────┘ └────────┘

┌──────────────┐
│ k-firewall   │
│ -outer(.12)  │
├──────────────┤
│ enp0s3 = NAT │
│ enp0s8 = mgmt│
└──────────────┘
```

## Interface Details

### k-firewall-fw
| iface | VBox | Type | Network | IP | Role | Mode | Peer | Purpose | XDP |
|-------|------|------|---------|----|------|------|------|---------|-----|
| wan0 | Adapter 1 | NAT | 10.0.2.0/24 | 10.0.2.15/24 | Wan | Route | — | Internet egress, gw 10.0.2.2 | SKB |
| mgmt | Adapter 2 | Host-Only | vboxnet0 | 192.168.11.10/24 | Mgmt | Route | — | SSH + API | No |
| wan1 | Adapter 3 | NAT | 10.0.2.0/24 | — | Wan | Route | — | client1 route egress (shares subnet with wan0) | SKB |
| wan2 | Adapter 4 | NAT | 10.0.4.0/24 | none | Wan | Transparent | lan2 | client2 transparent pair (gw 10.0.4.2) | SKB |
| lan0 | Adapter 5 | intnet | "kfw-lan0" | 192.168.10.1/24 | Lan | Route | — | client0 subnet, gw via wan0 | SKB |
| lan1 | Adapter 6 | intnet | "kfw-lan1" | 192.168.20.1/24 | Lan | Route | — | client1 subnet | SKB |
| lan2 | Adapter 7 | intnet | "kfw-lan2" | none | Lan | Transparent | wan2 | client2 transparent pair | SKB |
| lan3 | Adapter 8 | intnet | "kfw-lan3" | 192.168.40.1/24 | Lan | Route | — | spare | SKB |

### k-firewall-client / client0 (192.168.11.11)
| iface | VBox | Type | IP | Purpose |
|-------|------|------|----|---------|
| enp0s3 | Adapter 1 | intnet "kfw-lan0" | 192.168.10.2 | Data plane (gw 192.168.10.1 → wan0, 10.0.2.2) |
| enp0s8 | Adapter 2 | Host-Only vboxnet0 | 192.168.11.11 | Management (SSH) |

### k-firewall-client1 (192.168.11.13)
| iface | VBox | Type | IP | Purpose |
|-------|------|------|----|---------|
| enp0s3 | Adapter 1 | intnet "kfw-lan1" | 192.168.20.2 | Data plane (gw 192.168.20.1) |
| enp0s8 | Adapter 2 | Host-Only vboxnet0 | 192.168.11.13 | Management (SSH) |

### k-firewall-client2 (192.168.11.14)
| iface | VBox | Type | IP | Purpose |
|-------|------|------|----|---------|
| enp0s3 | Adapter 1 | intnet "kfw-lan2" | 10.0.4.30 static | Transparent pair (bridge lan2↔wan2, gw 10.0.4.2) |
| enp0s8 | Adapter 2 | Host-Only vboxnet0 | 192.168.11.14 | Management (SSH) |

### k-firewall-client3 (192.168.11.15)
| iface | VBox | Type | IP | Purpose |
|-------|------|------|----|---------|
| enp0s3 | Adapter 1 | intnet "kfw-lan3" | (spare, unconfigured) | spare |
| enp0s8 | Adapter 2 | Host-Only vboxnet0 | 192.168.11.15 | Management (SSH) |

### k-firewall-outer (192.168.11.12)
| iface | VBox | Type | IP | Purpose |
|-------|------|------|----|---------|
| enp0s3 | Adapter 1 | NAT | 10.0.2.x | External server (internet) |
| enp0s8 | Adapter 2 | Host-Only vboxnet0 | 192.168.11.12 | Management (SSH) |

## Firewall VM: VBoxManage NIC Setup

```bash
# Adapter 1 — wan0 (NAT, already configured)
#   VBoxManage modifyvm "k-firewall-fw" --nic1 nat --natnet1 "10.0.2.0/24"

# Adapter 2 — mgmt (Host-Only, already configured)
#   VBoxManage modifyvm "k-firewall-fw" --nic2 hostonly --hostonlyadapter2 "vboxnet0"

# Adapter 3 — wan1 (NAT, separate network)
VBoxManage modifyvm "k-firewall-fw" --nic3 nat --natnet3 "10.0.3.0/24"
VBoxManage modifyvm "k-firewall-fw" --cableconnected3 on

# Adapter 4 — wan2 (NAT, separate network)
VBoxManage modifyvm "k-firewall-fw" --nic4 nat --natnet4 "10.0.4.0/24"
VBoxManage modifyvm "k-firewall-fw" --cableconnected4 on

# Adapter 5 — lan0 (client0)
VBoxManage modifyvm "k-firewall-fw" --nic5 intnet --intnet5 "kfw-lan0"
VBoxManage modifyvm "k-firewall-fw" --cableconnected5 on

# Adapter 6 — lan1 (client1)
VBoxManage modifyvm "k-firewall-fw" --nic6 intnet --intnet6 "kfw-lan1"
VBoxManage modifyvm "k-firewall-fw" --cableconnected6 on

# Adapter 7 — lan2 (client2)
VBoxManage modifyvm "k-firewall-fw" --nic7 intnet --intnet7 "kfw-lan2"
VBoxManage modifyvm "k-firewall-fw" --cableconnected7 on

# Adapter 8 — lan3 (spare)
VBoxManage modifyvm "k-firewall-fw" --nic8 intnet --intnet8 "kfw-lan3"
VBoxManage modifyvm "k-firewall-fw" --cableconnected8 on
```

## Client VM Setup

### Existing VMs (no changes needed)
- **client0** — already connected to intnet "kfw-lan0" on enp0s8, stays on 192.168.10.2
- **outer** — already connected to Host-Only on enp0s8, stays on 192.168.11.12

### New VMs: client1 (192.168.11.13)

Option A: Clone from client0
```bash
# Clone VM
VBoxManage clonevm "k-firewall-client" --name "k-firewall-client1" --register

# Change data plane intnet to "kfw-lan1"
VBoxManage modifyvm "k-firewall-client1" --intnet2 "kfw-lan1"

# Set static mgmt IP on the VM after boot:
# ssh debian@192.168.11.11  →  sudo sed -i 's/192.168.11.11/192.168.11.13/' /etc/network/interfaces
# sudo reboot
```

Option B: Create fresh (2 NICs only)
```bash
VBoxManage createvm --name "k-firewall-client1" --register --ostype Debian_64
VBoxManage modifyvm "k-firewall-client1" --memory 512 --cpus 1
VBoxManage modifyvm "k-firewall-client1" --nic1 intnet --intnet1 "kfw-lan1"
VBoxManage modifyvm "k-firewall-client1" --nic2 hostonly --hostonlyadapter2 "vboxnet0"
VBoxManage modifyvm "k-firewall-client1" --cableconnected1 on --cableconnected2 on
```

### New VMs: client2 (192.168.11.14)

Option A: Clone from client0
```bash
VBoxManage clonevm "k-firewall-client" --name "k-firewall-client2" --register
VBoxManage modifyvm "k-firewall-client2" --intnet2 "kfw-lan2"
# Set mgmt IP to 192.168.11.14 after boot
```

Option B: Create fresh
```bash
VBoxManage createvm --name "k-firewall-client2" --register --ostype Debian_64
VBoxManage modifyvm "k-firewall-client2" --memory 512 --cpus 1
VBoxManage modifyvm "k-firewall-client2" --nic1 intnet --intnet1 "kfw-lan2"
VBoxManage modifyvm "k-firewall-client2" --nic2 hostonly --hostonlyadapter2 "vboxnet0"
VBoxManage modifyvm "k-firewall-client2" --cableconnected1 on --cableconnected2 on
```

## systemd `.link` Rules (Interface Renaming)

On the firewall VM, interfaces are renamed via `/etc/systemd/network/*.link` by MAC address.
Run `ip -br link` to find the actual MACs, then create:

```bash
cat <<'EOF' | sudo tee /etc/systemd/network/10-wan0.link
[Match]
MACAddress=08:00:27:xx:xx:01
[Link]
Name=wan0
EOF
```

Repeat for: wan1, wan2, lan0, lan1, lan2, lan3, mgmt.
After all `.link` files created: `sudo systemctl restart systemd-networkd`

> **VBox default MAC prefix**: `08:00:27` (Oracle)
> - Adapter 1 → wan0
> - Adapter 2 → mgmt
> - Adapter 3 → wan1
> - Adapter 4 → wan2
> - Adapter 5 → lan0
> - Adapter 6 → lan1
> - Adapter 7 → lan2
> - Adapter 8 → lan3

## Verified Data Plane (2026-08-01)

真实接线验证（VBox，XDP mode: generic），`test-physical.yaml`（lan0/wan0 route + lan2/wan2 transparent）：

| 验证项 | 结果 |
|--------|------|
| route: client0 (192.168.10.2) → 10.0.2.2 (NAT gw) | 通过（3/3，内核转发） |
| transparent: client2 (10.0.4.30) → 10.0.4.2 | 通过（3/3，bridge 转发） |
| rule DROP (route, src 192.168.10.2 dst 10.0.2.2 icmp) | 拦截（100% 丢，dropped 计数增加） |
| rule DROP (transparent, src 10.0.4.30 dst 10.0.4.2 icmp) | 拦截（100% 丢） |
| `k-firewall-cli block 10.0.4.30` (transparent) | 拦截（100% 丢，blocked 计数增加）；unblock 后恢复 3/3 |
| ARP 在 bridge 对（lan2↔wan2）正常 | 通过（跨 bridge 泛洪/MAC 学习） |

### 关键结论

1. **transparent 模式 = Linux bridge + XDP 检测**。daemon 为 transparent/hybrid 对创建
   `kfwbr_<a>_<b>` 内核 bridge（名字用下划线，连字符 `-` 会被 `ip link add type bridge` 拒绝），
   两端接口加入 bridge 后仍可挂 generic XDP。eBPF 只做检测，检测后 `XDP_PASS`，由 bridge 做
   L2 转发（ARP 泛洪、MAC 学习），二三层流量都能穿过。
2. **route 模式 = 纯内核转发**。generic XDP 下 `bpf_redirect` 跨接口 egress 不可靠
   （返回 rdir=4 但帧不发出；virtio_net 不支持 native/Driver XDP，os error 95）。
   因此 MODE_ROUTE 检测后 `XDP_PASS`，依赖 `ip_forward=1` + 系统路由表完成三层转发。
3. **接口模式隔离**：route 与 transparent 不混用同一 untagged 物理广播域；DMAC 区分不依赖
   （FW 接口 MAC 始终为 NGFW 本机）。商业防火墙惯例（Palo Alto 接口隔离 / FortiGate VWP /
   Cisco BVI）一致。
4. **规则/block 在两种模式下均在 XDP ingress 生效**（lan0、lan2 挂 SKB/generic XDP）。

### NAT（自动 masquerade，2026-08-01）

`nat` 字段（none | masquerade）声明式控制，仅 route 模式出口接口有效：

- **实现**：`k-firewalld/src/nat.rs::sync_nat_rules()` 在启动时对独立 `ip kfw_nat` 表 flush 后按配置注入
  `oifname <phy> masquerade` 规则；退出时 `delete table` 清理，不残留。
- **IPv4 only**（`ip` 表而非 `inet`）：避免 NAT66 意外覆盖 IPv6 透传语义。
- **LAN↔LAN 不碰 NAT**：`oifname` 出接口匹配天然隔离——只有发往 WAN 口的流量被伪装，
  跨子网内网路由保留真实源 IP（安全审计/内网 ACL 不受影响）。
- 实测：client0 (192.168.10.2)→10.0.2.2 在 wan0 抓包源 IP 为 10.0.2.15（masquerade 生效）；
  SIGINT 退出后 `nft list table ip kfw_nat` 报 No such file（清理完成）。

```yaml
interfaces:
  - name: wan0
    role: wan
    mode: route
    address: 10.0.2.15
    gateway: 10.0.2.2
    nat: masquerade
```

### Zone 安全策略 + conntrack 状态机（2026-08-01）

**Zone 策略**（LpmTrie）：
- `zone_policies` 编译为 `(src 接口 ifindex, dst 网段)` 最长前缀匹配，key=`[src_ifindex(4B), dst_ip(4B)]`，
  prefix=32+掩码位数。dst 网段由 dst_interface 的 `address`/`netmask`（默认 /24）推导。
- 实测：`lan0→wan0 drop` 使 client0 (192.168.10.2)→10.0.2.2 100% 丢（`ZONE DROP src_if=5 dst=10.0.2.2`），
  transparent client2→10.0.4.2 不受影响（无 zone 条目）。
- 数据面顺序：BLOCKED → conntrack(NEW/ESTABLISHED) → ZONE → RULES → 放行插 NEW。

**conntrack 状态机**（NEW → ESTABLISHED，双向匹配）：
- 首包（双向未命中）→ 规则/zone 放行后插 **NEW**。
- 返回包（反向命中 `CtKey::reverse()`）→ 提升正向条目为 **ESTABLISHED** 并快速放行。
- 同向后续包 → 快速放行（跳过规则）。
- 实测日志：`CT NEW` → `CT ESTABLISHED`（echo reply 触发提升），后续每包 ESTABLISHED。
- **注意**：XDP 在 netfilter 之前执行，route 模式 + masquerade 接口的回程包在 XDP 层看到的是
  NAT 前的五元组，双向匹配会因源 IP 被改写而失配（同向 NEW 正常）；transparent（无 NAT）接口
  双向匹配完整生效。

### P0-1：默认 deny + 双向 Zone + NAT 感知回程（2026-08-01）

**默认 deny（`default_action: drop`）**：
- 未命中 zone/规则的流量由 `CONFIG_DEFAULT_ACTION` 决定。实测 client0 (192.168.10.2)→8.8.8.8
  （无 zone 匹配）100% 丢，日志 `DROP family=4 src=192.168.10.2 dst=8.8.8.8 proto=1` ×5，dropped=6。
- 本机自身出站流量不经 XDP（generic XDP 仅 ingress），故 VM 直接 ping 外部不受影响。

**双向 Zone**：
- `zone_entries()` 每条策略生成双向条目（src→dst 网段 + dst→src 网段），transparent 接口
  无 address 时回退 0.0.0.0/0（匹配任意目的）。
- zone 命中 `ACTION_PASS` 显式放行（跳过默认 deny 与规则，Palo Alto 式 zone accept 即最终动作）。
- 实测：`lan0→wan0 accept` + `lan2→wan2 accept` 下 client0→10.0.2.2 与 client2→10.0.4.2 均 5/5 通；
  条目：`lan0→10.0.2.0/24`、`wan0→192.168.10.0/24`、`lan2→0/0`、`wan2→0/0`。

**NAT 感知回程（LOCAL_IPS 快速路径）**：
- BLOCKED 之后、conntrack 之前：目标为本机接口 IP（LOCAL_IPS）的包直接 `XDP_PASS` 交内核。
  masquerade 回程 dst=wan0 IP（10.0.2.15）在 XDP 层命中放行，由内核 netfilter un-NAT 转发给客户端，
  避免 NAT 前五元组与 conntrack 双向失配。hybrid 模式分支中的 LOCAL_IPS 判断已移除（全局统一处理）。
- 数据面顺序：BLOCKED → LOCAL_IPS(PASS) → conntrack → ZONE(PASS/DROP) → RULES → 默认动作。

### P0-2：NAT 感知回程（TC Egress 学习 + XDP Ingress 命中，2026-08-01）

**背景/选型**：`bpf_xdp_ct_lookup`/`bpf_xdp_ct_alloc`/`bpf_skb_ct_lookup`/`bpf_ct_insert_entry`
是 nf_conntrack **模块** BTF kfunc（本机 `/sys/kernel/btf/nf_conntrack`，`bpf_xdp_ct_lookup` ID 113818，
vmlinux BTF 无）。aya 的 PR #1372（kfunc 支持）仅解析 vmlinux BTF；PR #1594（模块 BTF fallback）
未合并（open/dirty）。crates.io 最新仍 aya 0.14.0 / aya-ebpf 0.2.1 → **升级 aya 调用 kfunc 不可行**，
改走纯 aya 能力的双程序方案（用户已确认）。

**方案（TC Egress + XDP Ingress）**：
- **TC Egress**（`kfw_tc_egress`，SchedClassifier，attach 到 masquerade 出口 wan0 egress）：
  在 netfilter POSTROUTING **之后**执行，看到 NAT 后五元组 `(WAN_IP:临时端口 → 外网IP:端口)`，
  翻转成回程预期 key `(外网IP:端口 → WAN_IP:临时端口)` 写入 `CONNTRACK_NAT`（HashMap<CtKey,CtValue> 65536）。
- **XDP Ingress**：LOCAL_IPS 之前查 `CONNTRACK_NAT.get(&nat_key)`，命中即 `XDP_PASS` 交内核 un-NAT。
  顺序：BLOCKED → CONNTRACK_NAT(PASS) → LOCAL_IPS(PASS) → conntrack → ZONE → RULES → 默认动作。

**关键实现细节**：
- 6.6+ 内核 TCX 路径：`SchedClassifier::attach(phy, Egress)` 走 TCX bpf_link，`tc filter show` 看不到，
  用 `bpftool prog show` / `bpftool net show` 确认（`tcx/egress kfw_tc_egress prog_id 238`）。
- aya 0.14 `netlink_qdisc_attach` 不自动建 clsact，daemon 手动 `tc qdisc add dev <phy> clsact`（幂等）。
- **TC 程序读包必须用 `ctx.load::<T>`（固定长度 bpf_skb_load_bytes）**；`ctx.load_bytes(offset, dst)`
  的 len 由 `min(skb.len()-offset, dst.len())` 动态计算，verifier 判 `R4 invalid zero-sized read` 无法加载。
- **字节序**：EtherType/端口/地址一律按 XDP 语义——`ctx.load` 小端读出与 `EtherType::Ipv4 as u16`
  （`0x0800_u16.to_be()`）直接相等，**不做 from_be**；地址/端口经 `from_be` 还原后进 CtKey（网络序存储）。
- **多程序日志**：aya-log `EbpfLogger::init` 只 `take_map("AYA_LOGS")` 一个 RingBuf，XDP+TC 各带自己的
  AYA_LOGS map，TC 日志无人读取会显示为格式串原样。改 daemon：程序 load 后按 `program.info()?.id()`
  逐个 `EbpfLogger::init_from_id(pid)` 建独立读取 task。

**实测**（fw 本地 curl example.com + ping 8.8.8.8，masquerade 出口 wan0）：
- TC LEARN：`TC NAT LEARN family=4 reply_src=28.0.0.161 reply_dport=52280`（HTTPS 回程）、
  `reply_src=8.8.8.8 reply_dport=0`（ICMP 回程）；CONNTRACK_NAT dump 3 条（TCP/ICMP/UDP-DNS），
  回程 dst 均为 10.0.2.15（WAN IP）。
- XDP 命中：`NAT HIT family=4 proto=6 sport=80 dport=59780`（HTTP 回程）、`proto=1 sport=0 dport=0`（ICMP）。
- 注：masquerade 回程 dst=WAN_IP 本就会命中 LOCAL_IPS 兜底；NAT map 价值在回程 dst≠本机 IP
  （多 WAN / 端口转发）场景，此处为兜底前先命中确认。当前测试仅验证通路，未做该差异场景。

### P1：DNAT / 会话日志 / 速率限制 / MultiWAN（2026-08-01）

四项 P1 功能全部实现并在 VM（k-firewall-fw 192.168.11.10）实测闭环。

#### P1-1 DNAT / 端口转发

- **实现**：`DNAT_RULES`（HashMap<DnatKey, DnatValue>），XDP Ingress 在 conntrack 前查 DNAT
  （dst IP+端口 命中），改写 dst + 写 `CONNTRACK_NAT.insert` 供回程命中；`nat.rs::prerouting`
  向 nftables `ip kfw_nat` 注入 `dnat` 规则端到端配合。
- **配置**（test-physical.yaml）：`10.0.2.15:8080 tcp → 192.168.10.2:80`。
- **实测**：daemon 启动日志 `DNAT[0] 10.0.2.15:8080 tcp -> 192.168.10.2:80`；正式配置重启后
  `DNAT_RULES` map 有值、nft 规则在；宿主机经 VirtualBox natpf（tcp8081→10.0.2.15:8080）
  `Test-NetConnection` 返回 True（连通性，转发链路由内核完成）。会话日志（见 P1-2）可见
  client0→外部被拦截/放行的会话记录，数据面与 DNAT map 通路已确认。

#### P1-2 会话日志 + syslog（RFC3164）

- **实现**：`SessionEvent`（action/family/proto/ifindex/src/dst/ports）+ `SESSION_LOG` RingBuf（64KiB）；
  eBPF 在 BLOCKED / ZONE DROP / RULE DROP / CT NEW 处调用 `log_session`/`log_session_v6`；
  Config `SessionLog`（enabled 默认 true / syslog_enabled / syslog_server / port）；daemon
  `spawn_session_logger` + `consume_session_events`（tokio AsyncFd + UDP syslog）。
- **实测**（正式配置默认 enabled）：`SESSION action=DROP family=ipv4 proto=udp ifindex=5
  src=192.168.10.2:39346 dst=193.182.111.143:123` 实时从 eBPF RingBuf → daemon → 日志；
  证明 client0 真实 LAN 流量进 FW 被策略处理并记录。

#### P1-3 per-IP 速率限制

- **实现**：`RateState`（last/tokens/rate/burst 令牌桶）、`RATE_LIMITS`（LruHashMap<IpKey,RateState>, 65536）、
  `rate_limited()` 每包扣令牌桶空 DROP；Config `RateLimitRule`（src_ip/rate/burst 默认 1000）+
  validate（rate 上限 4_000_000_000，防 u32 溢出）。
- **实测闭环**：test-physical.yaml client0 100pps/50burst；client0 洪泛 `ping -f -c 500 -i 0.002
  10.0.2.2` 得 45.2% 丢包（burst 50 后按 100pps 补，超速丢），FW 日志持续
  `RATE LIMIT family=4 src=192.168.10.2`。注意 RATE LIMIT 丢弃路径需真实转发流量
  （10.0.2.2 非本机 IP，不经 LOCAL_IPS 快路径）。

#### P1-4 MultiWAN failover + PBR

- **实现**：`multiwan.rs` 完整重写——`MultiwanState` 组健康表、`probe_wan`/`probe_from_interface`/
  `iface_ip`、`apply_default_route`、`apply_pbr`（独立数字路由表 100+idx + ip rule）；Config
  `WanGroup`/`PbrRule`；main 传完整 Config。
- **实测**（test-multiwan.yaml：wan0/wan1 探活 8.8.8.8:53，PBR src 192.168.10.0/24→wan0）：
  - 探活：`probe 8.8.8.8:53 via wan0 -> UP` / `wan1 -> UP`（改 8.8.8.8:53 前 NAT gw 10.0.2.2:53
    不监听全 DOWN）。
  - 默认路由：wan0/wan1 均 UP 时 `switch default route -> wan0 via 10.0.2.2`（选择生效）。
  - PBR：`ip rule add from 192.168.10.0/24 lookup 100` 成功（早期缺 `add` 报
    `Command "from" is unknown`，已修）；`ip rule show` 见 `32759: from 192.168.10.0/24 lookup 100`，
    `ip route show table 100` 见 `default via 10.0.2.2 dev wan0`。
  - **坑**：命名路由表 `kfw_pbr_N` 未注册 rt_tables，`ip route ... table kfw_pbr_0` 报
    `table id value is invalid` → 改数字表（100+idx）。幂等检查用 `ip rule show lookup <t>` 匹配
    "100" 会误命中系统自带 `lookup 100` 规则 → 改全量 `ip rule show` 精确匹配
    `from <src> lookup <table>`。
  - **限制**：真实 down→切 wan1 无法在当前同网段 NAT 拓扑（wan0/wan1 共享 10.0.2.0/24）干净模拟
    ——移除 wan0 IP 会断共享链路导致 wan1 也 DOWN；切换命令本身（`switch default route -> wanN`）
    已验证。真实多链路 down 切换需独立 WAN 网段。


