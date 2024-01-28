ARCH ?= amd64

ifeq ($(ARCH),amd64)
	CARCH ?= x86
else
	CARCH ?= $(ARCH)
endif

GOBIN := $(shell realpath .)/gobin
PATH += :$(GOBIN)

BPFDEF := bpf_$(CARCH)_bpfel.go

BPF2GO_CFLAGS := \
		 -v \
		 -g \
		 -O2 \
		 -std=gnu11 \
		 -nostdinc \
		 -Ilibbpf-bootstrap \
		 -Ilibbpf-bootstrap/vmlinux/$(CARCH)

build: bin/netfilter_exporter

bin/netfilter_exporter: $(wildcard *.go) $(BPFDEF) bpf_nf_counter_key_string.go
	CGO_ENABLED=0 GOOS=linux GOARCH="$(ARCH)" go build -o "$@" .

.PHONY: generate
generate: $(BPFDEF) bpf_nf_counter_key_string.go

$(BPFDEF): bpf.go bpf/bpf.c go.mod $(GOBIN)/bpf2go
	env \
		GOBIN="$(GOBIN)" \
		BPF2GO_CFLAGS="$(BPF2GO_CFLAGS)" \
		BPF_TARGET="$(ARCH)" \
		go generate "$<"

bpf_nf_counter_key_string.go: bpf_nf_counter_key.go $(BPFDEF) $(GOBIN)/stringer
	GOBIN="$(GOBIN)" go generate "$<"

.PHONY: go-tools
go-tools: $(GOBIN)/bpf2go $(GOBIN)/stringer

$(GOBIN)/bpf2go: go.mod
	GOBIN="$(GOBIN)" go install github.com/cilium/ebpf/cmd/bpf2go

$(GOBIN)/stringer: go.mod
	GOBIN="$(GOBIN)" go install golang.org/x/tools/cmd/stringer

.PHONY: clean
clean:
	rm -rfv *_bpfel.*o *_string.go bin gobin
