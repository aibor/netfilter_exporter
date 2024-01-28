# netfilter_exporter

Simple prometheus exporter for netfilter internal metrics gathered using eBPF.

Currently, only IP fragment count metrics are implemented. But, they can easily 
be extended with more counters on further kprobes.

## Build

Clang/LLVM is required for building the eBPF object file.

Checkout the repository with submodules:

```
git clone --recurse-submodules https://github.com/aibor/netfilter_exporter
```

Build the binary:

```
make build
```
