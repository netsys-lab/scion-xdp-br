// Copyright (c) 2022 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef MAPS_H_GUARD
#define MAPS_H_GUARD

#include "common.h"
#include "bpf/types.h"
#include "bpf_helpers.h"
#include <linux/bpf.h>


/// \brief Maps a tuple of device port, IP and UDP port to a SCION AS interface identifier (a small
/// positive integer).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct ingress_addr)); // Destination IP, port and ingress interface
    __uint(value_size, sizeof(u32)); // Corresponding AS interface
    __uint(max_entries, 16);
} ingress_map SEC(".maps");

/// \brief Stores information on how to rewrite and redirect a packet destined to a certain AS
/// egress interface as identified by SCION's AS interface identifier.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32)); // AS egress interface
    __uint(value_size, sizeof(struct fwd_info)); // Information on how to forward the packet
    __uint(max_entries, 16);
} egress_map SEC(".maps");

/// \brief Stores the source IP address and source UDP port of the AS internal interfaces.
/// \details The internal interfaces are identified by Linux interface index, therefore we can have
/// only one UDP underlay connection per physical interface.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32)); // Interface index
    __uint(value_size, sizeof(struct interface)); // Corresponding IP and UDP port
    __uint(max_entries, 16);
} int_iface_map SEC(".maps");

#ifdef ENABLE_HF_CHECK
/// \brief Stores the hop field verification keys in expanded form.
/// \details At the moment only key 0 is used.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32)); // Index
    __uint(value_size, sizeof(struct hop_key)); // AES key for MAC verification
    __uint(max_entries, 8);
} mac_key_map SEC(".maps");
#endif

/// \brief One-to-one mapping of physical interfaces for bpf_redirect_map API.
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 16);
} tx_port_map SEC(".maps");

/// \brief Packet and byte counters per port, CPU, and verdict.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct port_stats));
    __uint(max_entries, COUNTER_ENUM_COUNT);
} port_stats_map SEC(".maps");

/// \brief Scratchpad memory for passing values between functions and reducing the utilization of
/// stack space.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct scratchpad));
    __uint(max_entries, 1);
} scratchpad_map SEC(".maps");

#endif // MAPS_H_GUARD
