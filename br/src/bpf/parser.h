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

#include "common.h"
#include "constants.h"
#include "headers.h"

#include "bpf/types.h"
#include "bpf/builtins.h"
#include "bpf/scion.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>

inline void* parse_underlay(struct scratchpad *this, struct headers *hdr, void *data, void *data_end);
inline void* parse_scion(struct scratchpad *this, struct headers *hdr, void *data, void *data_end);
inline void* parse_scion_path(struct scratchpad *this, struct headers *hdr, void *data, void *data_end);


/// \brief Parse the Ethernet header and IP/UDP underlay.
__attribute__((__always_inline__))
inline void* parse_underlay(
    struct scratchpad *this, struct headers *hdr, void *data, void *data_end)
{
    this->verdict = VERDICT_NOT_SCION;

    // Ethernet
    hdr->eth = data;
    data += sizeof(*hdr->eth);
    if (data > data_end) return NULL;
    memcpy(this->eth.dst, hdr->eth->h_dest, ETH_ALEN);
    memcpy(this->eth.src, hdr->eth->h_source, ETH_ALEN);

    // IP
    switch (hdr->eth->h_proto)
    {
#ifdef ENABLE_IPV4
    case htons(ETH_P_IP):
        hdr->ip.v4 = data;
        data += sizeof(*hdr->ip.v4);
        if (data > data_end) return NULL;
        this->ip.family = AF_INET;
        this->ip_residual -= (this->ip.v4.dst = hdr->ip.v4->daddr);
        this->ip_residual -= (this->ip.v4.src = hdr->ip.v4->saddr);
        this->udp_residual = this->ip_residual;
        // TTL is not part of UDP checksum
        this->ip_residual -= (this->ip.v4.ttl = hdr->ip.v4->ttl);
        // Skip options
        size_t skip = 4 * (size_t)hdr->ip.v4->ihl - sizeof(*hdr->ip.v4);
        if (skip > 40) return NULL;
        data += skip;
    #ifdef ENABLE_IPV6
        memset(this->ip.v6, 0, sizeof(this->ip.v6));
    #endif
        if (hdr->ip.v4->protocol != IPPROTO_UDP) return NULL;
        break;
#endif
#ifdef ENABLE_IPV6
    case htons(ETH_P_IPV6):
        this->hdr.ip.v6 = data;
        data += sizeof(*this->hdr.ip.v6);
        if (data > data_end) return NULL;
        this->ip.family = AF_INET6;
        memcpy(this->ip.v6.dst, &this->hdr.ip.v6->daddr, 16);
        memcpy(this->ip.v6.src, &this->hdr.ip.v6->saddr, 16);
        this->ip.v6.hop_limit = this->hdr.ip.v6->hop_limit;
        // TODO: checksum residual
    #ifdef ENABLE_IPV4
        memset(this->ip.v4, 0, sizeof(this->ip.v4));
    #endif
        if (this->hdr.ip.v6->nexthdr != IPPROTO_UDP) return NULL;
#endif
    default:
        return NULL;
    }

    // UDP
    hdr->udp = data;
    data += sizeof(*hdr->udp);
    if (data > data_end) return NULL;
    this->udp_residual -= (this->udp.dst = hdr->udp->dest);
    this->udp_residual -= (this->udp.src = hdr->udp->source);

    return data;
};

/// \brief Parse the SCION headers.
__attribute__((__always_inline__))
inline void* parse_scion(struct scratchpad *this, struct headers *hdr, void *data, void *data_end)
{
    this->verdict = VERDICT_PARSE_ERROR;

    // SCION common and address header
    hdr->scion = data;
    data += sizeof(*hdr->scion);
    if (data > data_end) return NULL;
    if (SC_GET_VER(hdr->scion) != 0)
    {
        this->verdict = VERDICT_NOT_IMPLEMENTED;
        return NULL;
    }

    // Skip over AS-internal addresses
    data += 8 + 4 * SC_GET_DL(hdr->scion) + 4 * SC_GET_SL(hdr->scion);
    if (data > data_end) return NULL;

    // Path
    this->path_type = hdr->scion->type;
    switch (hdr->scion->type)
    {
#ifdef ENABLE_SCION_PATH
    case SC_PATH_TYPE_SCION:
        return parse_scion_path(this, hdr, data, data_end);
#endif
    default:
        this->verdict = VERDICT_NOT_IMPLEMENTED;
        return NULL;
    }
}

#ifdef ENABLE_SCION_PATH
/// \brief Parse standard SCION path.
__attribute__((__always_inline__))
inline void* parse_scion_path(
    struct scratchpad *this, struct headers *hdr, void *data, void *data_end)
{
    this->verdict = VERDICT_PARSE_ERROR;

    // Meta header
    hdr->scion_path.meta = data;
    data += sizeof(*hdr->scion_path.meta);
    if (data > data_end) return NULL;
    this->udp_residual -= *hdr->scion_path.meta;

    this->path.scion.h_meta = ntohl(*hdr->scion_path.meta);
    this->path.scion.seg0 = PATH_GET_SEG0_HOST(this->path.scion.h_meta);
    this->path.scion.seg1 = PATH_GET_SEG1_HOST(this->path.scion.h_meta);
    this->path.scion.seg2 = PATH_GET_SEG2_HOST(this->path.scion.h_meta);

    // Calculate number of info and hop fields
    u32 num_inf = (this->path.scion.seg0 > 0) + (this->path.scion.seg1 > 0)
        + (this->path.scion.seg2 > 0);
    u32 num_hf = this->path.scion.seg0 + this->path.scion.seg1 + this->path.scion.seg2;
    this->path.scion.num_inf = num_inf;
    this->path.scion.num_hf = num_hf;

    // Find current info and hop field
    // A second info field is needed if the path changes over from one segment to the next and
    // the same router is both the AS ingress and egress point.
    u32 curr_inf = this->path.scion.curr_inf = PATH_GET_CURR_INF_HOST(this->path.scion.h_meta);
    u32 curr_hf = this->path.scion.curr_hf = PATH_GET_CURR_HF_HOST(this->path.scion.h_meta);
    this->path.scion.segment_switch = 0;

    // Current info field
    struct infofield *inf = data + curr_inf * sizeof(struct infofield);
    hdr->scion_path.inf = inf;
    if (((void*)inf + sizeof(struct infofield)) > data_end) return NULL;
    this->path.scion.seg_id[0] = inf->seg_id;
    this->udp_residual -= inf->seg_id;

    // Next info field
    if (curr_inf + 1 < num_inf)
    {
        ++inf;
        if (((void*)inf + sizeof(struct infofield)) > data_end) return NULL;
        this->path.scion.seg_id[1] = inf->seg_id;
    }

    // Current hop field
    hdr->scion_path.hf = data
        + num_inf *sizeof(struct infofield) + curr_hf * sizeof(struct hopfield);
    if (((void*)hdr->scion_path.hf + sizeof(struct hopfield)) > data_end) return NULL;

    return data;
}
#endif // ENABLE_SCION_PATH
