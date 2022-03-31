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

#ifndef FIB_LOOKUP_H_GUARD
#define FIB_LOOKUP_H_GUARD

#include "common.h"
#include "constants.h"
#include "headers.h"
#include "maps.h"

#include "bpf/types.h"
#include "bpf/builtins.h"
#include "bpf/scion.h"

#include "bpf_helpers.h"
#include <linux/bpf.h>

#include <stdbool.h>


/// \brief Initialize the xdp_fib_lookup structure with common data.
__attribute__((__always_inline__))
inline void init_fib_lookup(struct scratchpad *this, struct headers *hdr, struct xdp_md* ctx)
{
    memset(&this->fib_lookup, 0, sizeof(struct bpf_fib_lookup));
    this->fib_lookup.family = this->ip.family;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->fib_lookup.l4_protocol = hdr->ip.v4->protocol;
        this->fib_lookup.tos = hdr->ip.v4->tos;
        this->fib_lookup.tot_len = ntohs(hdr->ip.v4->tot_len);
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        this->fib_lookup.l4_protocol = this->hdr.ip.v6->nexthdr;
        this->fib_lookup.tot_len = ntohs(this->hdr.ip.v6->payload_len);
        break;
#endif
    default:
        break;
    }
    this->fib_lookup.ifindex = ctx->ingress_ifindex;
}

// Ignore warning on call to bpf_fib_lookup in inline functions
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstatic-in-inline"

/// \brief Prepare forwarding the packet to the next AS.
/// \return Index of the switch egress interface or -1 on error.
__attribute__((__always_inline__))
inline int fib_lookup_as_egress(struct scratchpad *this, struct xdp_md* ctx, struct fwd_info *fwd)
{
    this->udp.dst = this->fib_lookup.dport = fwd->redirect.dst_port;
    this->udp.src = this->fib_lookup.sport = fwd->redirect.src_port;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->ip.v4.dst = this->fib_lookup.ipv4_dst = fwd->redirect.ipv4.dst;
        this->ip.v4.src = this->fib_lookup.ipv4_src = fwd->redirect.ipv4.src;
        this->ip.v4.ttl = DEFAULT_TTL;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->fib_lookup.ipv6_dst, fwd->redirect.ipv6.dst, 16);
        memcpy(this->ip.v6.dst, fwd->redirect.ipv6.dst, 16);
        memcpy(this->fib_lookup.ipv6_src, fwd->redirect.ipv6.src, 16);
        memcpy(this->ip.v6.dst, fwd->redirect.ipv6.src, 16);
        this->ip.v6.hop_limit = DEFAULT_TTL;
        break;
#endif
    default:
        break;
    }

    int res = bpf_fib_lookup(ctx, &this->fib_lookup, sizeof(struct bpf_fib_lookup), 0);
    if (res != BPF_FIB_LKUP_RET_SUCCESS)
    {
        switch (res)
        {
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            this->verdict = VERDICT_FIB_LKUP_DROP;
            return -1;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            this->verdict = VERDICT_FIB_LKUP_PASS;
            return -1;
        }
    }

    memcpy(this->eth.dst, this->fib_lookup.dmac, ETH_ALEN);
    memcpy(this->eth.src, this->fib_lookup.smac, ETH_ALEN);

    return this->fib_lookup.ifindex;
}

/// \brief Prepare forwarding the packet to another border router in the same AS.
/// \return Index of the switch egress interface or -1 on error.
__attribute__((__always_inline__))
inline int fib_lookup_egress_br(struct scratchpad *this, struct xdp_md* ctx, struct fwd_info *fwd)
{
    this->udp.dst = this->fib_lookup.dport = fwd->egress_br.port;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->ip.v4.dst = this->fib_lookup.ipv4_dst = fwd->egress_br.ipv4;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->fib_lookup.ipv6_dst, fwd->egress_br.ipv6, 16);
        memcpy(this->ip.v6.dst, fwd->egress_br.ipv6, 16);
        break;
#endif
    default:
        break;
    }

    int res = bpf_fib_lookup(ctx, &this->fib_lookup, sizeof(struct bpf_fib_lookup), 0);
    if (res != BPF_FIB_LKUP_RET_SUCCESS)
    {
        switch (res)
        {
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            this->verdict = VERDICT_FIB_LKUP_DROP;
            return -1;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            this->verdict = VERDICT_FIB_LKUP_PASS;
            return -1;
        }
    }

    memcpy(this->eth.dst, this->fib_lookup.dmac, ETH_ALEN);
    memcpy(this->eth.src, this->fib_lookup.smac, ETH_ALEN);

    // Internal interface lookup
    struct interface *iface;
    u32 key = this->fib_lookup.ifindex;
    iface = bpf_map_lookup_elem(&int_iface_map, &key);
    if (!iface)
    {
        this->verdict = VERDICT_ABORT;
        return -1;
    }

    this->udp.src = iface->port;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->ip.v4.src = iface->ipv4;
        this->ip.v4.ttl = DEFAULT_TTL;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->ip.v6.src, iface->ipv6, 16);
        this->ip.v6.hop_limit = DEFAULT_TTL;
        break;
#endif
    default:
        break;
    }

    return this->fib_lookup.ifindex;
}

/// \brief Prepare forwarding a packet received from a border router in our AS to another border
// router in this AS.
/// \return Index of the switch egress interface or -1 on error.
__attribute__((__always_inline__))
inline int fib_lookup_ip_forward(struct scratchpad *this, struct headers *hdr, struct xdp_md* ctx, struct fwd_info *fwd)
{
    this->fib_lookup.dport = hdr->udp->dest;
    this->fib_lookup.sport = hdr->udp->source;
    switch (this->ip.family)
    {
#ifdef ENABLE_IPV4
    case AF_INET:
        this->fib_lookup.ipv4_dst = hdr->ip.v4->daddr;
        this->fib_lookup.ipv4_src = hdr->ip.v4->saddr;
        break;
#endif
#ifdef ENABLE_IPV6
    case AF_INET6:
        memcpy(this->fib_lookup.ipv6_dst, &this->hdr.ip.v6->daddr, 16);
        memcpy(this->fib_lookup.ipv6_src, &this->hdr.ip.v6->saddr, 16);
        break;
#endif
    default:
        break;
    }

    int res = bpf_fib_lookup(ctx, &this->fib_lookup, sizeof(struct bpf_fib_lookup), 0);
    if (res != BPF_FIB_LKUP_RET_SUCCESS)
    {
        switch (res)
        {
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            this->verdict = VERDICT_FIB_LKUP_DROP;
            return -1;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            this->verdict = VERDICT_FIB_LKUP_PASS;
            return -1;
        }
    }

    memcpy(this->eth.dst, this->fib_lookup.dmac, ETH_ALEN);
    memcpy(this->eth.src, this->fib_lookup.smac, ETH_ALEN);
    --this->ip.v4.ttl;
    return this->fib_lookup.ifindex;
}

#pragma clang diagnostic pop

#endif // FIB_LOOKUP_H_GUARD
