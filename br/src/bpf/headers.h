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

#ifndef HEADERS_H_GUARD
#define HEADERS_H_GUARD

#include "bpf/types.h"
#include "bpf/scion.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

/// \brief Pointers into the packet buffer.
/// Must be kept on the stack so the verifier is able to keep track of pointer validity.
struct headers
{
    struct ethhdr *eth;
    union {
        struct iphdr *v4;
        struct ipv6hdr *v6;
    } ip;
    struct udphdr *udp;
    struct scionhdr *scion;
    union {
#ifdef ENABLE_SCION_PATH
        struct {
            u32 *meta;
            struct infofield *inf;
            struct hopfield *hf;
        } scion_path;
#endif
    };
};

#endif // HEADERS_H_GUARD
