SCION XDP Border Router
=======================

This repository contains a BPF XDP application intended to accelerate the reference
[SCION](https://github.com/scionproto/scion) border router by forwarding some common packet types
directly in XDP.

[A more up to date development version is available at https://github.com/lschulz/bpf-experiments]

### Overview
- [/aes](/aes) Implementation of AES-CMAC for use in XDP as required by SCION.
- [/br](/br) The SCION XDP border router.
  - [/br/evaluation](/br/evaluation) contains some preliminary evaluation results.
- [/libbpfpp](/libbpfpp) C++ wrappers for libbpf
- [/libbpfpy](/libbpfpy) Python helpers for interfacing with libbpf
- [/scion](/scion) Some scripts for testing the XDP router in a dockerized local SCION topology.

Building
--------
Clone with `--recurse-submodules` or initialize the submodules after cloning:
```bash
git submodule update --init
```

First build libbpf:
```bash
pushd libbpf/src
make
popd
```

Build the repository by invoking cmake directly
```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
make
```
or run simply run `make`.

See the various subdirectories for instructions on how to run tests etc.
