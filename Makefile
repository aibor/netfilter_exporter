GOBIN := $(shell realpath .)/gobin
PATH += :$(GOBIN)

export GOBIN

build: bin/netfilter_exporter

bin/netfilter_exporter: $(wildcard *.go) bpf_bpfel.go bpf_nf_counter_key_string.go
	go build -o $@ .

.PHONY: generate
generate: bpf_bpfel.go bpf_nf_counter_key_string.go

bpf_bpfel.go: bpf.go bpf/bpf.c go.mod $(GOBIN)/bpf2go
	go generate $<

bpf_nf_counter_key_string.go: bpf_nf_counter_key.go bpf_bpfel.go $(GOBIN)/stringer
	go generate $<

.PHONY: go-tools
go-tools: $(GOBIN)/bpf2go $(GOBIN)/stringer

$(GOBIN)/bpf2go: go.mod
	go install github.com/cilium/ebpf/cmd/bpf2go

$(GOBIN)/stringer: go.mod
	go install golang.org/x/tools/cmd/stringer

.PHONY: clean
clean:
	rm -rfv *_bpfel.*o *_string.go bin gobin
