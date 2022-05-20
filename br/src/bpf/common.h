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

#ifndef COMMON_H_GUARD
#define COMMON_H_GUARD

#include "bpf/types.h"
#include "bpf/scion.h"
#include "aes/aes.h"

#include <linux/bpf.h>

#ifdef __INTELLISENSE__
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_SCION_PATH
#define ENABLE_HF_CHECK
#endif


#define MAKE_VERDICT(action, reason) ((action & 0x07) | (reason << 3))

enum counter {
    COUNTER_UNDEFINED,         ///< Unknown packet status
    COUNTER_SCION_FORWARD,     ///< Packet was forwarded by XDP
    COUNTER_PARSE_ERROR,       ///< Could not parse packet as valid SCION
    COUNTER_NOT_SCION,         ///< Packet is not UDP with SCION overlay
    COUNTER_NOT_IMPLEMENTED,   ///< Unsupported SCION header type
    COUNTER_NO_INTERFACE,      ///< Cannot match SCION packet to BR interface
    COUNTER_UNDERLAY_MISMATCH, ///< Translation between IPv4 and IPv6 underlay needed
    COUNTER_ROUTER_ALERT,      ///< Router alert flag is set
    COUNTER_FIB_LKUP_DROP,     ///< FIB lookup failed, dropping packet
    COUNTER_FIB_LKUP_PASS,     ///< FIB lookup failed, full network stack assistance required
    COUNTER_INVALID_HF,        ///< Hop field is invalid
    COUNTER_ENUM_COUNT,        // always last
};

enum verdict {
    VERDICT_ABORT             = MAKE_VERDICT(XDP_ABORTED,  COUNTER_UNDEFINED),
    VERDICT_DROP              = MAKE_VERDICT(XDP_DROP,     COUNTER_UNDEFINED),
    VERDICT_PASS              = MAKE_VERDICT(XDP_PASS,     COUNTER_UNDEFINED),
    VERDICT_TX                = MAKE_VERDICT(XDP_TX,       COUNTER_UNDEFINED),
    VERDICT_SCION_FORWARD     = MAKE_VERDICT(XDP_REDIRECT, COUNTER_SCION_FORWARD),
    VERDICT_PARSE_ERROR       = MAKE_VERDICT(XDP_DROP,     COUNTER_PARSE_ERROR),
    VERDICT_NOT_SCION         = MAKE_VERDICT(XDP_PASS,     COUNTER_NOT_SCION),
    VERDICT_NOT_IMPLEMENTED   = MAKE_VERDICT(XDP_PASS,     COUNTER_NOT_IMPLEMENTED),
    VERDICT_NO_INTERFACE      = MAKE_VERDICT(XDP_DROP,     COUNTER_NO_INTERFACE),
    VERDICT_UNDERLAY_MISMATCH = MAKE_VERDICT(XDP_PASS,     COUNTER_UNDERLAY_MISMATCH),
    VERDICT_ROUTER_ALERT      = MAKE_VERDICT(XDP_PASS,     COUNTER_ROUTER_ALERT),
    VERDICT_FIB_LKUP_DROP     = MAKE_VERDICT(XDP_DROP,     COUNTER_FIB_LKUP_DROP),
    VERDICT_FIB_LKUP_PASS     = MAKE_VERDICT(XDP_PASS,     COUNTER_FIB_LKUP_PASS),
    VERDICT_INVALID_HF        = MAKE_VERDICT(XDP_DROP,     COUNTER_INVALID_HF),
};

/// \brief Key for ingress IFID lookup.
struct ingress_addr
{
    // Only one of ipv4 and ipv6 is allowed to be non-zero.
#ifdef ENABLE_IPV4
    u32 ipv4;    // in network byte order
#endif
#ifdef ENABLE_IPV6
    u32 ipv6[4]; // in network byte order
#endif
    u16 port;    // in network byte order
    u16 ifindex; // in host byte order
};

/// \brief Expanded AES key and AES-CMAC subkey for hop field validation.
struct hop_key
{
    struct aes_key_schedule key;
    struct aes_block subkey;
};

/// \brief Underlay addresses of a SCION inter-AS link.
struct ext_link
{
    u32 ip_family;         // AF_INET or AF_INET6
    union {
#ifdef ENABLE_IPV4
        struct {
            u32 remote;    // in network byte order
            u32 local;     // in network byte order
        } ipv4;
#endif
#ifdef ENABLE_IPV6
        struct {
            u32 remote[4]; // in network byte order
            u32 local[4];  // in network byte order
        } ipv6;
#endif
    };
    u16 remote_port;       // in network byte order
    u16 local_port;        // in network byte order
};

/// \brief IP address and UDP port of an AS-internal BR interface.
struct int_iface
{
    u32 ip_family;   // AF_INET or AF_INET6
    union {
#ifdef ENABLE_IPV4
        u32 ipv4;    // in network byte order
#endif
#ifdef ENABLE_IPV6
        u32 ipv6[4]; // in network byte order
#endif
    };
    u16 port;        // in network byte order
};

/// \brief Underlay addresses for packet rewriting and redirection.
struct fwd_info
{
    /// Nonzero if the next hop is outside of the current AS.
    u32 fwd_external;

    union {
        /// Local and remote underlay addresses of the inter-AS link to the next-hop AS.
        /// Valid if `fwd_external != 0`.
        struct ext_link link;

        /// Internal interface address of the next-hop sibling BR.
        /// Valid if `fwd_external == 0`.
        struct int_iface sibling;
    };
};

/// \brief Packet and byte counters of a single BR port.
struct port_stats {
    u64 verdict_bytes[COUNTER_ENUM_COUNT];
    u64 verdict_pkts[COUNTER_ENUM_COUNT];
};

/// \brief Scratchpad memory for variables that do not fit on the stack.
struct scratchpad
{
    // Verdict if the last operation failed
    u32 verdict;

    // Constants set by the control plane
    // TODO

    // Metadata and copies of updatable fields
    struct
    {
        u8 dst[6];
        u16 _padding1;
        u8 src[6];
        u16 _padding2;
    } eth;

    struct ip_struct {
        u32 family; // AF_INET or AF_INET6
#ifdef ENABLE_IPV4
        struct
        {
            u32 dst;
            u32 src;
            u8 ttl;
        } v4;
#endif
#ifdef ENABLE_IPV6
        struct
        {
            u32 dst[4];
            u32 src[4];
            u8 hop_limit;
        } v6;
#endif
    } ip;

    struct {
        u16 dst;
        u16 src;
    } udp;

    u32 path_type;

    union {
        struct {
            u32 h_meta; // path meta field in host byte order
            u32 curr_inf, curr_hf;
            u16 seg_id[2];
            u32 segment_switch; // one if a segment switch occurred
            u32 seg0, seg1, seg2;
            u32 num_inf, num_hf;
        } scion;
    } path;

    // Residuals of the IP and UDP checksum
    u64 ip_residual;
    u64 udp_residual;

    // Input/output for FIB lookup
    struct bpf_fib_lookup fib_lookup;

    // Interface the packet will be redirected to
    int egress_ifindex;

#ifdef ENABLE_HF_CHECK
    // Input for mac verification
    u32 verify_mac_mask;
    struct macinput macinput[2];
    u64 mac[2];
#endif
};

#endif // COMMON_H_GUARD
