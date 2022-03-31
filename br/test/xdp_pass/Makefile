CLANG := clang
BPFTOOL := bpftool

BPF_CFLAGS = -Wall -Winline -target bpf -O2 -g

VETH ?= veth0
PIN_PATH ?= /sys/fs/bpf/xdp_pass


xdp_pass.o : xdp_pass.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(PIN_PATH) : xdp_pass.o
	$(BPFTOOL) prog load xdp_pass.o $(PIN_PATH)

attach: $(PIN_PATH)
	$(BPFTOOL) net attach xdp pinned $(PIN_PATH) dev $(VETH)

detach:
	$(BPFTOOL) net detach xdp dev $(VETH)

clean:
	rm $(PIN_PATH)
	rm xdp_pass.o
