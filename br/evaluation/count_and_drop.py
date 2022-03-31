#!/usr/bin/python3

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
            print("   CPU {} |".format(i), end="")
        print()

        while True:
            time.sleep(1)
            t1 = time.perf_counter()
            delta = t1 - t0
            t0 = t1
            new_values = bpf["count"].values()[0]

            print("|", end="")
            for old, new in zip(old_values, new_values):
                print("{:>8.3g}".format((new.packets - old.packets) / delta), end=" |")
            print()

            old_values = new_values

    except KeyboardInterrupt:
        pass

finally:
    bpf.remove_xdp(args.iface)
