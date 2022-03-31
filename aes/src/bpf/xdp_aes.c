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

#include "bpf/types.h"
#include "bpf/builtins.h"
#include "aes/aes.h"

#include "bpf_helpers.h"
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <stddef.h>
#include <stdint.h>

char _license[] SEC("license") = "Dual MIT/GPL";


struct key_schedule {
    struct aes_key_schedule keys;
    struct aes_block subkeys[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct key_schedule));
    __uint(max_entries, 8);
} aes_key_map SEC(".maps");


struct testhdr
{
    struct aes_cmac mac;
    __u32 time;
    __u32 seq;
    char data[16];
};

#define SCAN_HDR(type, hdr, cursor) \
    type *hdr = cursor; \
    if (cursor + sizeof(*hdr) <= data_end) \
        cursor += sizeof(*hdr); \
    else \
        return XDP_PASS

SEC(".xdp")
int xdp_aes(struct xdp_md* ctx)
{
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    void *cursor = data;

    // Parse Ethernet
    SCAN_HDR(struct ethhdr, eth, cursor);
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP
    SCAN_HDR(struct iphdr, ip, cursor);
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Parse UDP
    SCAN_HDR(struct udphdr, udp, cursor);
    if (udp->dest != htons(6500))
        return XDP_PASS;

    // Parse Test Header
    SCAN_HDR(struct testhdr, test, cursor);

    // __bpf_printk("Parse successful\n");

    // Load AES key
    u32 key_index = 0;
    struct key_schedule *sched = bpf_map_lookup_elem(&aes_key_map, &key_index);
    if (!sched) return XDP_PASS;

    // Calculate AES-CMAC
    __u64 t0 = bpf_ktime_get_ns();
    struct aes_cmac mac = {};
    aes_cmac_16bytes(
        (struct aes_block *)&test->data,
        &sched->keys, &sched->subkeys[0], &mac);
    __u32 delta = (__u32)(bpf_ktime_get_ns() - t0);

    // Update packet headers
    u64 csum = ~ntohs(udp->check);

    csum += delta + ~ntohl(test->time) + 1;
    test->time = htonl(delta);

    #pragma unroll
    for (unsigned int i = 0; i < 4; ++i)
    {
        csum += ntohl(mac.w[i]) + ~ntohl(test->mac.w[i]) + 1;
        test->mac.w[i] = mac.w[i];
    }

    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = ~csum - 1;
    if (csum == 0) csum = 0xffff;
    udp->check = htons(csum);

    return XDP_PASS;
}
