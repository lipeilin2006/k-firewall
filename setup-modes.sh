#!/bin/bash
# 三模式联合测试环境：route / transparent / hybrid（veth + 两个 netns）
# 清理旧环境（幂等）
for ns in ns1 ns2; do sudo ip netns del "$ns" 2>/dev/null; done
for v in ra0 ra1 rb0 rb1 ta0 ta1 tb0 tb1 ha0 ha1 hb0 hb1; do
  sudo ip link del "$v" 2>/dev/null
done

set -e

# ---- 路由模式对：ra0/ra1(ns1) + rb0/rb1(ns2) ----
sudo ip link add ra0 type veth peer name ra1
sudo ip link add rb0 type veth peer name rb1
sudo ip netns add ns1
sudo ip netns add ns2
sudo ip link set ra1 netns ns1
sudo ip link set rb1 netns ns2

sudo ip addr add 10.0.5.1/24 dev ra0
sudo ip addr add 10.0.6.1/24 dev rb0
sudo ip link set ra0 up
sudo ip link set rb0 up

sudo ip netns exec ns1 ip addr add 10.0.5.2/24 dev ra1
sudo ip netns exec ns1 ip link set ra1 up
sudo ip netns exec ns1 ip route add 10.0.6.0/24 via 10.0.5.1
sudo ip netns exec ns2 ip addr add 10.0.6.2/24 dev rb1
sudo ip netns exec ns2 ip link set rb1 up
sudo ip netns exec ns2 ip route add 10.0.5.0/24 via 10.0.6.1

# ---- 透明模式对：ta0/ta1(ns1) + tb0/tb1(ns2)，ta0 <-> tb0 串接 ----
sudo ip link add ta0 type veth peer name ta1
sudo ip link add tb0 type veth peer name tb1
sudo ip link set ta1 netns ns1
sudo ip link set tb1 netns ns2
sudo ip link set ta0 up
sudo ip link set tb0 up
sudo ip netns exec ns1 ip link set ta1 up
sudo ip netns exec ns2 ip link set tb1 up
sudo ip netns exec ns1 ip addr add 10.0.7.2/24 dev ta1
sudo ip netns exec ns2 ip addr add 10.0.8.2/24 dev tb1
# 静态路由跨网段（透明 XDP 不查路由，只重定向，MAC 需预置）
sudo ip netns exec ns1 ip route add 10.0.8.0/24 dev ta1
sudo ip netns exec ns2 ip route add 10.0.7.0/24 dev tb1

# ---- 混合模式对：ha0/ha1(ns1) + hb0/hb1(ns2)，ha0 <-> hb0 串接 ----
sudo ip link add ha0 type veth peer name ha1
sudo ip link add hb0 type veth peer name hb1
sudo ip link set ha1 netns ns1
sudo ip link set hb1 netns ns2
sudo ip link set ha0 up
sudo ip link set hb0 up
sudo ip netns exec ns1 ip link set ha1 up
sudo ip netns exec ns2 ip link set hb1 up
sudo ip netns exec ns1 ip addr add 10.0.11.2/24 dev ha1
sudo ip netns exec ns2 ip addr add 10.0.12.2/24 dev hb1
sudo ip netns exec ns1 ip route add 10.0.12.0/24 dev ha1
sudo ip netns exec ns2 ip route add 10.0.11.0/24 dev hb1
# hybrid 本机路径可达：ha0 有 10.0.9.1，ns1 经 ha1 直连；宿主加回程路由（egress 不经 XDP）
sudo ip addr add 10.0.9.1/24 dev ha0
sudo ip netns exec ns1 ip route add 10.0.9.0/24 dev ha1
sudo ip route add 10.0.11.0/24 dev ha0

# ---- 预置邻居（透明/混合 XDP 不处理 ARP，需要静态 MAC 才能转发 ICMP）----
# 需要两端 veth 的 MAC；veth 对端在 netns 里，此处通过 ip link 读取宿主端 MAC。
# 取宿主端 ta0/tb0/ha0/hb0 的 MAC，作为对端 ns 发往宿主的下一跳 MAC。
# 注：veth 对端 MAC 可由宿主端 ifindex 关联，此处直接写 netns 内 MAC。
TA0_MAC=$(sudo ip -br link show ta0 | awk '{print $3}')
TB0_MAC=$(sudo ip -br link show tb0 | awk '{print $3}')
HA0_MAC=$(sudo ip -br link show ha0 | awk '{print $3}')
HB0_MAC=$(sudo ip -br link show hb0 | awk '{print $3}')

# 透明：ns1 发 10.0.8.2 走 ta0（宿主）→ tb0 → ns2 的 tb1。
#   ns1 侧下一跳 MAC = tb1 的 MAC（即对端 ns2 的 tb1）。需要读取 netns 内 MAC。
TB1_MAC=$(sudo ip netns exec ns2 ip -br link show tb1 | awk '{print $3}')
TA1_MAC=$(sudo ip netns exec ns1 ip -br link show ta1 | awk '{print $3}')
HB1_MAC=$(sudo ip netns exec ns2 ip -br link show hb1 | awk '{print $3}')
HA1_MAC=$(sudo ip netns exec ns1 ip -br link show ha1 | awk '{print $3}')

sudo ip netns exec ns1 ip neigh replace 10.0.8.2 lladdr "$TB1_MAC" dev ta1 nud permanent
sudo ip netns exec ns2 ip neigh replace 10.0.7.2 lladdr "$TA1_MAC" dev tb1 nud permanent
sudo ip netns exec ns1 ip neigh replace 10.0.12.2 lladdr "$HB1_MAC" dev ha1 nud permanent
sudo ip netns exec ns2 ip neigh replace 10.0.11.2 lladdr "$HA1_MAC" dev hb1 nud permanent
# hybrid 本机路径：ns1 直连 ha0 的 10.0.9.1，预置邻居使 ICMP 能到达宿主内核
sudo ip netns exec ns1 ip neigh replace 10.0.9.1 lladdr "$HA0_MAC" dev ha1 nud permanent

echo "=== route pair ==="
sudo ip -br addr show ra0 rb0
echo "=== transparent pair ==="
sudo ip -br addr show ta0 tb0
echo "=== hybrid pair ==="
sudo ip -br addr show ha0 hb0
echo "=== ns1 ==="
sudo ip netns exec ns1 ip -br addr show | grep -E 'ra1|ta1|ha1'
echo "=== ns2 ==="
sudo ip netns exec ns2 ip -br addr show | grep -E 'rb1|tb1|hb1'
echo "setup done"
