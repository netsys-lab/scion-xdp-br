#include <linux/bpf.h>

char _license[] __attribute__((section("license"))) = "Dual MIT/GPL";

__attribute__((section("xdp")))
int xdp_pass(struct xdp_md* ctx)
{
    return XDP_PASS;
}
