(Partial) implementation of AES and AES-CMAC for BPF
====================================================

Compiling
---------
Run `make` in this directory.

Tests
-----
### C++ unit tests
Run `build/aes_test`.

### BPF tests
Some automated tests can be executed by running
```bash
sudo test/test.py
```

Manual testing:
1. Run `test/setup.py` to create a test network namespace and veth interface pair.
2. Load the AES-XDP program: `sudo build/xdp_loader build/xdp_combined.o veth0`
3. Start receiver: `test/receiver.py 10.1.0.1 6500`
4. Send packets: `sudo ip netns exec xdp_test test/sender.py 10.1.0.1 6500`
5. Capture packets with tcpdump: `sudo tcpdump -nn -vv -i veth0`
6. When done, delete the network namespace with `sudo ip netns delete xdp_test`.
