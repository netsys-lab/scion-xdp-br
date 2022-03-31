#!/bin/bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_DIR=$(readlink -f "$SCRIPT_DIR/../../..")
NETNS="$PROJECT_DIR/utils/netns.bash"

# Add network namespaces
sudo "$NETNS" prepare
sudo "$NETNS" add sw0
sudo "$NETNS" add sw1
sudo "$NETNS" add sw2

# Create veth pairs
sudo ip link add veth0 type veth peer name veth1 netns sw0
sudo ip link add veth2 type veth peer name veth3 netns sw0
sudo ip link add veth4 netns sw1 type veth peer name veth5 netns sw0
sudo ip link add veth6 netns sw2 type veth peer name veth7 netns sw0
sudo ip link add veth8 type veth peer name veth9 netns sw1
sudo ip link add veth10 type veth peer name veth11 netns sw1
sudo ip link add veth12 type veth peer name veth13 netns sw2
sudo ip link add veth14 type veth peer name veth15 netns sw2

# Set deterministic MAC addresses
sudo ip link set dev veth0 addr 02:00:00:00:00:00
sudo ip netns exec sw0 ip link set dev veth1 addr 02:00:00:00:00:01
sudo ip link set dev veth2 addr 02:00:00:00:00:02
sudo ip netns exec sw0 ip link set dev veth3 addr 02:00:00:00:00:03
sudo ip netns exec sw1 ip link set dev veth4 addr 02:00:00:00:00:04
sudo ip netns exec sw0 ip link set dev veth5 addr 02:00:00:00:00:05
sudo ip netns exec sw2 ip link set dev veth6 addr 02:00:00:00:00:06
sudo ip netns exec sw0 ip link set dev veth7 addr 02:00:00:00:00:07
sudo ip link set dev veth8 addr 02:00:00:00:00:08
sudo ip netns exec sw1 ip link set dev veth9 addr 02:00:00:00:00:09
sudo ip link set dev veth10 addr 02:00:00:00:00:0A
sudo ip netns exec sw1 ip link set dev veth11 addr 02:00:00:00:00:0B
sudo ip link set dev veth12 addr 02:00:00:00:00:0C
sudo ip netns exec sw2 ip link set dev veth13 addr 02:00:00:00:00:0D
sudo ip link set dev veth14 addr 02:00:00:00:00:0E
sudo ip netns exec sw2 ip link set dev veth15 addr 02:00:00:00:00:0F

# Configure host interfaces in global namespace
sudo ip addr add dev veth0 10.1.1.1/24
sudo ip addr add dev veth2 10.1.2.1/24
sudo ip addr add dev veth8 10.1.3.1/24
sudo ip addr add dev veth10 10.1.4.1/24
sudo ip addr add dev veth12 10.1.5.1/24
sudo ip addr add dev veth14 10.1.6.1/24
sudo ip link set dev veth0 up
sudo ip link set dev veth2 up
sudo ip link set dev veth8 up
sudo ip link set dev veth10 up
sudo ip link set dev veth12 up
sudo ip link set dev veth14 up

# Load trivial XDP programs on host side (required for XDP_TX and XDP_REDIRECT on veths)
make -C xdp_pass > /dev/null
sudo make -C xdp_pass attach VETH=veth0 > /dev/null
sudo make -C xdp_pass attach VETH=veth2 > /dev/null
sudo make -C xdp_pass attach VETH=veth8 > /dev/null
sudo make -C xdp_pass attach VETH=veth10 > /dev/null
sudo make -C xdp_pass attach VETH=veth12 > /dev/null
sudo make -C xdp_pass attach VETH=veth14 > /dev/null

# Bring interface on switch side up
sudo ip netns exec sw0 ip addr add dev veth1 10.1.1.2/24
sudo ip netns exec sw0 ip addr add dev veth3 10.1.2.2/24
sudo ip netns exec sw0 ip link set dev veth1 up
sudo ip netns exec sw0 ip link set dev veth3 up
sudo ip netns exec sw1 ip addr add dev veth9 10.1.3.2/24
sudo ip netns exec sw1 ip addr add dev veth11 10.1.4.2/24
sudo ip netns exec sw1 ip link set dev veth9 up
sudo ip netns exec sw1 ip link set dev veth11 up
sudo ip netns exec sw2 ip addr add dev veth13 10.1.5.2/24
sudo ip netns exec sw2 ip addr add dev veth15 10.1.6.2/24
sudo ip netns exec sw2 ip link set dev veth13 up
sudo ip netns exec sw2 ip link set dev veth15 up

# Configure links between switches
sudo ip netns exec sw1 ip addr add dev veth4 10.2.0.0/31
sudo ip netns exec sw0 ip addr add dev veth5 10.2.0.1/31
sudo ip netns exec sw2 ip addr add dev veth6 10.2.0.2/31
sudo ip netns exec sw0 ip addr add dev veth7 10.2.0.3/31
sudo ip netns exec sw1 ip link set dev veth4 up
sudo ip netns exec sw0 ip link set dev veth5 up
sudo ip netns exec sw2 ip link set dev veth6 up
sudo ip netns exec sw0 ip link set dev veth7 up

# Configure AS internal routing
sudo ip netns exec sw0 sysctl -w net.ipv4.ip_forward=1 > /dev/null
sudo ip netns exec sw1 ip route add 10.2.0.2/31 via 10.2.0.1 dev veth4
sudo ip netns exec sw2 ip route add 10.2.0.0/31 via 10.2.0.3 dev veth6

# Disable checksum offload
sudo ethtool --offload veth0 rx off tx off > /dev/null
sudo ethtool --offload veth2 rx off tx off > /dev/null
sudo ethtool --offload veth8 rx off tx off > /dev/null
sudo ethtool --offload veth10 rx off tx off > /dev/null
sudo ethtool --offload veth12 rx off tx off > /dev/null
sudo ethtool --offload veth14 rx off tx off > /dev/null
sudo ip netns exec sw0 ethtool --offload veth1 rx off tx off > /dev/null
sudo ip netns exec sw0 ethtool --offload veth3 rx off tx off > /dev/null
sudo ip netns exec sw0 ethtool --offload veth5 rx off tx off > /dev/null
sudo ip netns exec sw0 ethtool --offload veth7 rx off tx off > /dev/null
sudo ip netns exec sw1 ethtool --offload veth4 rx off tx off > /dev/null
sudo ip netns exec sw1 ethtool --offload veth9 rx off tx off > /dev/null
sudo ip netns exec sw1 ethtool --offload veth11 rx off tx off > /dev/null
sudo ip netns exec sw2 ethtool --offload veth6 rx off tx off > /dev/null
sudo ip netns exec sw2 ethtool --offload veth13 rx off tx off > /dev/null
sudo ip netns exec sw2 ethtool --offload veth15 rx off tx off > /dev/null

# Make sure ARP cache is populated
sudo ip netns exec sw0 ping -c 1 10.1.1.1
sudo ip netns exec sw0 ping -c 1 10.1.2.1
sudo ip netns exec sw0 ping -c 1 10.2.0.0
sudo ip netns exec sw0 ping -c 1 10.2.0.2
sudo ip netns exec sw1 ping -c 1 10.1.3.1
sudo ip netns exec sw1 ping -c 1 10.1.4.1
sudo ip netns exec sw2 ping -c 1 10.1.5.1
sudo ip netns exec sw2 ping -c 1 10.1.6.1
