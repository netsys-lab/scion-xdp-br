#!/bin/bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_DIR=$(readlink -f "$SCRIPT_DIR/../../..")
NETNS="$PROJECT_DIR/utils/netns.bash"

# Add network namespace
sudo "$NETNS" prepare
sudo "$NETNS" add sw0

# Create veth pairs
sudo ip link add veth0 type veth peer name veth1 netns sw0
sudo ip link add veth2 type veth peer name veth3 netns sw0
sudo ip link add veth4 type veth peer name veth5 netns sw0
sudo ip link add veth6 type veth peer name veth7 netns sw0

# Set deterministic MAC addresses
sudo ip link set dev veth0 addr 02:00:00:00:00:00
sudo ip netns exec sw0 ip link set dev veth1 addr 02:00:00:00:00:01
sudo ip link set dev veth2 addr 02:00:00:00:00:02
sudo ip netns exec sw0 ip link set dev veth3 addr 02:00:00:00:00:03
sudo ip link set dev veth4 addr 02:00:00:00:00:04
sudo ip netns exec sw0 ip link set dev veth5 addr 02:00:00:00:00:05
sudo ip link set dev veth6 addr 02:00:00:00:00:06
sudo ip netns exec sw0 ip link set dev veth7 addr 02:00:00:00:00:07

# Configure host interfaces in global namespace
sudo ip addr add dev veth0 10.1.1.1/24
sudo ip addr add dev veth0 fd00:f00d:cafe:1::1/64
sudo ip addr add dev veth2 10.1.2.1/24
sudo ip addr add dev veth2 fd00:f00d:cafe:2::1/64
sudo ip link set dev veth0 up
sudo ip link set dev veth2 up

# Load trivial XDP programs
make -C xdp_pass > /dev/null
sudo make -C xdp_pass attach VETH=veth0 > /dev/null
sudo make -C xdp_pass attach VETH=veth2 > /dev/null
sudo make -C xdp_pass attach VETH=veth4 > /dev/null
sudo make -C xdp_pass attach VETH=veth6 > /dev/null

# Bring interface on switch side up
sudo ip netns exec sw0 ip addr add dev veth1 10.1.1.2/24
sudo ip netns exec sw0 ip addr add dev veth1 fd00:f00d:cafe:1::2/64
sudo ip netns exec sw0 ip addr add dev veth3 10.1.2.2/24
sudo ip netns exec sw0 ip addr add dev veth3 fd00:f00d:cafe:2::2/64
sudo ip netns exec sw0 ip link set dev veth1 up
sudo ip netns exec sw0 ip link set dev veth3 up

# Configure links between switches
sudo ip addr add dev veth4 10.2.0.0/31
sudo ip addr add dev veth4 fd00:f00d:cafe:0::0/127
sudo ip netns exec sw0 ip addr add dev veth5 10.2.0.1/31
sudo ip netns exec sw0 ip addr add dev veth5 fd00:f00d:cafe:0::1/127
sudo ip addr add dev veth6 10.2.0.2/31
sudo ip addr add dev veth6 fd00:f00d:cafe:0::2/127
sudo ip netns exec sw0 ip addr add dev veth7 10.2.0.3/31
sudo ip netns exec sw0 ip addr add dev veth7 fd00:f00d:cafe:0::3/127
sudo ip link set dev veth4 up
sudo ip netns exec sw0 ip link set dev veth5 up
sudo ip link set dev veth6 up
sudo ip netns exec sw0 ip link set dev veth7 up

# Configure AS internal routing
sudo ip netns exec sw0 sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec sw0 sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null

# Disable checksum offload
sudo ethtool --offload veth0 rx off tx off > /dev/null
sudo ethtool --offload veth2 rx off tx off > /dev/null
sudo ethtool --offload veth4 rx off tx off > /dev/null
sudo ethtool --offload veth6 rx off tx off > /dev/null
sudo ip netns exec sw0 ethtool --offload veth1 rx off tx off > /dev/null
sudo ip netns exec sw0 ethtool --offload veth3 rx off tx off > /dev/null
sudo ip netns exec sw0 ethtool --offload veth5 rx off tx off > /dev/null
sudo ip netns exec sw0 ethtool --offload veth7 rx off tx off > /dev/null

# Make sure ARP cache is populated
sudo ip netns exec sw0 ping -c 1 10.1.1.1
sudo ip netns exec sw0 ping -c 1 10.1.2.1
sudo ip netns exec sw0 ping -c 1 10.2.0.0
sudo ip netns exec sw0 ping -c 1 10.2.0.2

sleep 2 # IPv6 needs some time
sudo ip netns exec sw0 ping -c 1 fd00:f00d:cafe:1::1
sudo ip netns exec sw0 ping -c 1 fd00:f00d:cafe:2::1
sudo ip netns exec sw0 ping -c 1 fd00:f00d:cafe:0::0
sudo ip netns exec sw0 ping -c 1 fd00:f00d:cafe:0::2
