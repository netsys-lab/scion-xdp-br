#!/usr/bin/python3
# Copyright (c) 2022 Lars-Christian Schulz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import time

from bcc import BPF

text = r"""
struct Counter
{
    u64 bytes, packets;
};

BPF_PERCPU_ARRAY(count, struct Counter, 1);

int count_and_drop(struct xdp_md* ctx)
{
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    u32 key = 0;
    struct Counter *cnt = count.lookup(&key);
    if (cnt)
    {
        cnt->bytes += (ctx->data_end - ctx->data);
        cnt->packets++;
    }

    return XDP_DROP;
}
"""

parser = argparse.ArgumentParser(
    description="Count packets received on an interface and drop them in XDP.")
parser.add_argument("-i", "--iface", required=True, help="Interface to attach to.")
args = parser.parse_args()

bpf = BPF(text=text)
count_and_drop = bpf.load_func("count_and_drop", BPF.XDP)

try:
    bpf.attach_xdp(args.iface, count_and_drop, BPF.XDP_FLAGS_DRV_MODE)
    try:
        t0 = time.perf_counter()
        old_values = bpf["count"].values()[0]

        print("Dropped packets per second:")
        print("|", end="")
        for i, _ in enumerate(old_values):
            print("    CPU {} |".format(i), end="")
        print("    Total |", end="")
        print()

        while True:
            time.sleep(1)
            t1 = time.perf_counter()
            delta = t1 - t0
            t0 = t1
            new_values = bpf["count"].values()[0]

            print("|", end="")
            total_pkts = 0
            for old, new in zip(old_values, new_values):
                pkts = new.packets - old.packets
                total_pkts += pkts
                print(" {:>8.3g}".format(pkts / delta), end=" |")
            print(" {:>8.3g}".format(total_pkts / delta), end=" |")
            print()

            old_values = new_values

    except KeyboardInterrupt:
        pass

finally:
    bpf.remove_xdp(args.iface)
