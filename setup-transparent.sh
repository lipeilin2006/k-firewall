#!/bin/bash
# 透明模式测试环境：ns1 --a1/a0-- XDP --b0/b1-- ns2
#   a0 peer b0（透明对端），ns1=10.0.5.2，ns2=10.0.6.2
set -e

sudo ip netns del ns1 2>/dev/null || true
sudo ip netns del ns2 2>/dev/null || true
sudo ip link del a0 2>/dev/null || true
sudo ip link del b0 2>/dev/null || true

sudo ip netns add ns1
sudo ip netns add ns2

sudo ip link add a0 type veth peer name a1
sudo ip link set a1 netns ns1
sudo ip link set a0 up
sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns1 ip addr add 10.0.5.2/24 dev a1
sudo ip netns exec ns1 ip link set a1 up

sudo ip link add b0 type veth peer name b1
sudo ip link set b1 netns ns2
sudo ip link set b0 up
sudo ip netns exec ns2 ip link set lo up
sudo ip netns exec ns2 ip addr add 10.0.6.2/24 dev b1
sudo ip netns exec ns2 ip link set b1 up

# ns1 直接 ping 10.0.6.2 需要路由；改用 ns1 -> 10.0.6.2（走 a0 透明转发到 b0）
sudo ip netns exec ns1 ip route add 10.0.6.0/24 dev a1
sudo ip netns exec ns2 ip route add 10.0.5.0/24 dev b1

# XDP 透明重定向只处理 IP；ARP（非 IP）会走 XDP_PASS 交给内核而不会被转发。
# 因此预置 ARP，让 ns1/ns2 直接以对端 MAC 发送 ICMP。
A1_MAC=$(sudo ip netns exec ns1 ip -br link show a1 | awk '{print $3}')
B1_MAC=$(sudo ip netns exec ns2 ip -br link show b1 | awk '{print $3}')
sudo ip netns exec ns1 ip neigh replace 10.0.6.2 lladdr "$B1_MAC" dev a1 nud permanent
sudo ip netns exec ns2 ip neigh replace 10.0.5.2 lladdr "$A1_MAC" dev b1 nud permanent

echo "=== a0/b0 ==="
sudo ip -br link show a0
sudo ip -br link show b0
echo "=== ns1 ==="
sudo ip netns exec ns1 ip -br addr
echo "=== ns2 ==="
sudo ip netns exec ns2 ip -br addr
echo "setup done"
