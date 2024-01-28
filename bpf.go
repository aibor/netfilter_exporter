package main

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate bpf2go -target $BPF_TARGET -type nf_counter_type -type nf_counter_key bpf bpf/bpf.c

type bpfState struct {
	objects bpfObjects
	links   map[string]link.Link
}

func (s *bpfState) Close() {
	for _, lnk := range s.links {
		lnk.Close()
	}
	s.objects.Close()
}

func bpfInit() (*bpfState, error) {
	state := new(bpfState)

	if err := loadBpfObjects(&state.objects, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %v", err)
	}

	kprobes := map[string]*ebpf.Program{
		"inet_frag_queue_insert": state.objects.KprobeInetFragQueueInsert,
	}

	state.links = make(map[string]link.Link, len(kprobes))

	for fn, prog := range kprobes {
		lnk, err := link.Kprobe(fn, prog, nil)
		if err != nil {
			state.Close()
			return nil, fmt.Errorf("attach kprobe %s: %v", fn, err)
		}
		state.links[fn] = lnk
	}

	return state, nil
}

func (s *bpfState) FetchCounters() (map[bpfNfCounterKey]uint64, error) {
	var cursor ebpf.BatchCursor

	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}

	batchKeys := make([]bpfNfCounterKey, 64)
	batchValues := make([]uint64, len(batchKeys)*possibleCPUs)

	counters := make(map[bpfNfCounterKey]uint64)

	for done := false; !done; {
		count, err := s.objects.NfCounters.BatchLookup(
			&cursor,
			batchKeys,
			batchValues,
			nil,
		)
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				done = true
			} else {
				return nil, err
			}
		}
		slog.Debug("fetched counters", "count", count, "done", done)

		for keyIdx, key := range batchKeys[:count] {
			var value uint64
			for i := 0; i < possibleCPUs; i++ {
				value += batchValues[keyIdx*possibleCPUs+i]
			}
			counters[key] = value
		}
	}

	return counters, nil
}
