#!/bin/bash

sudo ip netns add xdp_test
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns xdp_test

sudo ip addr add dev veth0 10.1.0.1/24
sudo ip link set dev veth0 up

sudo ip netns exec xdp_test ip addr add dev veth1 10.1.0.2/24
sudo ip netns exec xdp_test ip link set dev veth1 up

# Disable checksum offload
sudo ethtool --offload veth0 rx off tx off
sudo ip netns exec xdp_test ethtool --offload veth1 rx off tx off
