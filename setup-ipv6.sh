#!/bin/bash
# IPv6 路由模式 FIB 测试环境
#   ra0(fd00:1::1) <-> ra1(ns1 fd00:1::2)
#   rb0(fd00:2::1) <-> rb1(ns2 fd00:2::2)
set -e

sudo ip netns del ns1 2>/dev/null || true
sudo ip netns del ns2 2>/dev/null || true
sudo ip link del ra0 2>/dev/null || true
sudo ip link del rb0 2>/dev/null || true

sudo ip netns add ns1
sudo ip netns add ns2

# ra pair
sudo ip link add ra0 type veth peer name ra1
sudo ip link set ra1 netns ns1
sudo ip addr add fd00:1::1/64 dev ra0
sudo ip addr add 10.0.5.1/24 dev ra0
sudo ip link set ra0 up
sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns1 ip addr add fd00:1::2/64 dev ra1
sudo ip netns exec ns1 ip addr add 10.0.5.2/24 dev ra1
sudo ip netns exec ns1 ip link set ra1 up
sudo ip netns exec ns1 ip -6 route add default via fd00:1::1
sudo ip netns exec ns1 ip route add default via 10.0.5.1

# rb pair
sudo ip link add rb0 type veth peer name rb1
sudo ip link set rb1 netns ns2
sudo ip addr add fd00:2::1/64 dev rb0
sudo ip addr add 10.0.6.1/24 dev rb0
sudo ip link set rb0 up
sudo ip netns exec ns2 ip link set lo up
sudo ip netns exec ns2 ip addr add fd00:2::2/64 dev rb1
sudo ip netns exec ns2 ip addr add 10.0.6.2/24 dev rb1
sudo ip netns exec ns2 ip link set rb1 up
sudo ip netns exec ns2 ip -6 route add default via fd00:2::1
sudo ip netns exec ns2 ip route add default via 10.0.6.1

# IPv6 转发
sudo sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
sudo sysctl -w net.ipv6.conf.ra0.forwarding=1 >/dev/null
sudo sysctl -w net.ipv6.conf.rb0.forwarding=1 >/dev/null
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null

# IPv4 转发
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

# 取 veth 对端真实 MAC 并预置 ARP / NDP，保证首包即可走 FIB 快路径。
RA1_MAC=$(sudo ip netns exec ns1 ip -br link show ra1 | awk '{print $3}')
RB1_MAC=$(sudo ip netns exec ns2 ip -br link show rb1 | awk '{print $3}')
sudo ip -6 neigh replace fd00:2::2 lladdr "$RB1_MAC" dev rb0 nud permanent
sudo ip -6 neigh replace fd00:1::2 lladdr "$RA1_MAC" dev ra0 nud permanent
sudo ip neigh replace 10.0.6.2 lladdr "$RB1_MAC" dev rb0 nud permanent
sudo ip neigh replace 10.0.5.2 lladdr "$RA1_MAC" dev ra0 nud permanent

sudo ip6tables -P FORWARD ACCEPT || true

echo "=== ra0 ==="
sudo ip -br addr show ra0
echo "=== rb0 ==="
sudo ip -br addr show rb0
echo "=== NDP ra0 ==="
sudo ip -6 neigh show dev ra0
echo "=== NDP rb0 ==="
sudo ip -6 neigh show dev rb0
echo "=== ns1 routes ==="
sudo ip netns exec ns1 ip -6 route
echo "=== ns2 routes ==="
sudo ip netns exec ns2 ip -6 route
echo "=== ip6tables forward policy ==="
sudo ip6tables -L FORWARD -n | head -3
echo "setup done"
