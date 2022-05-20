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

#ifndef SCION_PATH_H_GUARD
#define SCION_PATH_H_GUARD

#include "common.h"
#include "constants.h"
#include "headers.h"

#include "bpf/types.h"
#include "bpf/builtins.h"
#include "bpf/scion.h"

#include "bpf_helpers.h"
#include <linux/bpf.h>

#include <stdbool.h>


__attribute__((__always_inline__))
inline void defer_verify_hop_field(
    struct scratchpad *this, unsigned int which,
    struct infofield *info, struct hopfield *hop, u16 beta)
{
#ifdef ENABLE_HF_CHECK
    // Set flag to enable mac verification at the end of packet processing
    this->verify_mac_mask |= (1 << which);

    // Prepare input for MAC calculation
    memset(&this->macinput[which], 0, sizeof(struct macinput));
    this->macinput[which].beta = beta;
    this->macinput[which].ts = info->ts;
    this->macinput[which].exp = hop->exp;
    this->macinput[which].ingress = hop->ingress;
    this->macinput[which].egress = hop->egress;

    // Store MAC from HF for comparison
    this->mac[which] = 0;
    memcpy(&this->mac[which], hop->mac, sizeof(hop->mac));
#endif
}

/// \brief AS ingress processing
__attribute__((__always_inline__))
inline bool scion_as_ingress(struct scratchpad *this, struct headers *hdr, void *data_end)
{
    // Full router must handle the packet if router alert flags are set
    if (hdr->scion_path.hf->flags & 0x03)
    {
        this->verdict = VERDICT_ROUTER_ALERT;
        return false;
    }

    // Hop field verifiaction and MAC chaining
    u16 beta = ntohs(this->path.scion.seg_id[0]);
    if (!INF_GET_CONS(hdr->scion_path.inf))
    {
        struct hopfield *hf = hdr->scion_path.hf;
        beta ^= (u16)hf->mac[1] | (((u16)hf->mac[0]) << 8);
    }
    defer_verify_hop_field(this, 0, hdr->scion_path.inf, hdr->scion_path.hf, htons(beta));
    if (!INF_GET_CONS(hdr->scion_path.inf))
        this->path.scion.seg_id[0] = htons(beta);

    // Switch to next path segment if necessary
    u32 seg_end = this->path.scion.seg0;
    if (this->path.scion.curr_inf >= 1) seg_end += this->path.scion.seg0;
    if (this->path.scion.curr_inf >= 2) seg_end += this->path.scion.seg0;
    u32 next_hf = this->path.scion.curr_hf + 1;
    if (next_hf >= this->path.scion.num_hf)
    {
        // Path ends in our AS
        // TODO: Deliver packet to the dispatcher
        this->verdict = VERDICT_NOT_IMPLEMENTED;
        return false;
    }
    if (next_hf < this->path.scion.num_hf && next_hf == seg_end)
    {
        // Advance to next path segment
        this->path.scion.segment_switch = 1;
        ++this->path.scion.curr_inf;
        ++this->path.scion.curr_hf;
        ++hdr->scion_path.hf;
        if (((void*)hdr->scion_path.hf + sizeof(struct hopfield)) > data_end)
        {
            this->verdict = VERDICT_PARSE_ERROR;
            return false;
        }
    }

    return true;
}

/// \brief AS egress processing
/// \return True if processing can continue, false on error (check this->verdict).
__attribute__((__always_inline__))
inline bool scion_as_egress(struct scratchpad *this, struct headers *hdr, u32 as_ing_ifid, void *data_end)
{
    this->verdict = XDP_ABORTED;

    // Full router must handle the packet if router alert flags are set
    if (hdr->scion_path.hf->flags & 0x03)
    {
        this->verdict = VERDICT_ROUTER_ALERT;
        return false;
    }

    // If segment_switch is one, we need to work with the second segment identifier.
    u32 seg_switch = this->path.scion.segment_switch;

    // If we have switched from one segment to another at the end of ingress processing,
    // we must use and update the new current hop field during egress processing.
    struct infofield *inf = hdr->scion_path.inf;
    if (seg_switch)
    {
        ++inf;
        if ((void*)(inf + 1) > data_end) return false;
    }

    u16 *seg_id_ptr = this->path.scion.seg_id;
    if (seg_switch) seg_id_ptr = this->path.scion.seg_id + 1;
    u16 beta = ntohs(*seg_id_ptr);
    if (as_ing_ifid == INTERNAL_IFACE) // avoid checking the same hop field twice
        defer_verify_hop_field(this, 1, hdr->scion_path.inf, hdr->scion_path.hf, htons(beta));
    if (INF_GET_CONS(inf))
    {
        struct hopfield *hf = hdr->scion_path.hf;
        u16 seg_id = beta ^ ((u16)hf->mac[1] | ((u16)hf->mac[0] << 8));
        *seg_id_ptr = htons(seg_id);
    }
    ++this->path.scion.curr_hf;

    return true;
}

#endif // SCION_PATH_H_GUARD
