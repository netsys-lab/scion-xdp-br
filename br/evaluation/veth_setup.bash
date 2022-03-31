#!/bin/bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_DIR=$(readlink -f "$SCRIPT_DIR/../..")

NETNS="$PROJECT_DIR/utils/netns.bash"

"$NETNS" prepare
"$NETNS" add br

ip link add veth0 type veth peer name veth1 netns br
ip link add veth2 type veth peer name veth3 netns br

ip addr add dev veth0 10.1.0.0/31
ip netns exec br ip addr add dev veth1 10.1.0.1/31
ip addr add dev veth2 10.1.0.2/31
ip netns exec br ip addr add dev veth3 10.1.0.3/31

ip link set dev veth0 addr 02:00:00:00:00:00
ip netns exec br ip link set dev veth1 addr 02:00:00:00:00:01
ip link set dev veth2 addr 02:00:00:00:00:02
ip netns exec br ip link set dev veth3 addr 02:00:00:00:00:03

ip link set dev veth0 up
ip netns exec br ip link set dev veth1 up
ip link set dev veth2 up
ip netns exec br ip link set dev veth3 up

ethtool --offload veth0 rx off tx off > /dev/null
ip netns exec br ethtool --offload veth1 rx off tx off > /dev/null
ethtool --offload veth2 rx off tx off > /dev/null
ip netns exec br ethtool --offload veth3 rx off tx off > /dev/null

sudo ip netns exec br ping -c 1 10.1.0.0 > /dev/null
sudo ip netns exec br ping -c 1 10.1.0.2 > /dev/null
