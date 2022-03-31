#!/bin/bash

ip netns exec br ip link add veth_bridge type bridge
ip netns exec br ip link set veth1 master veth_bridge
ip netns exec br ip link set veth3 master veth_bridge
ip netns exec br ip link set veth_bridge up
