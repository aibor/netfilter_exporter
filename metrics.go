package main

import (
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	NfCounterLabelIpVersion = "ip_version"
	NfCounterLabelInterface = "interface"
)

type Metrics map[bpfNfCounterType]prometheus.GaugeVec

func newMetrics(prefix string) Metrics {
	labels := []string{NfCounterLabelIpVersion, NfCounterLabelInterface}

	metrics := make(map[bpfNfCounterType]prometheus.GaugeVec)
	for c := bpfNfCounterType(0); c < bpfNfCounterTypeNF_COUNTER_KEY_LEN; c++ {
		slog.Debug("add metric", "metric", c.String())

		opts := prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_%s", prefix, strings.ToLower(c.String())),
		}

		metrics[c] = *promauto.NewGaugeVec(opts, labels)
	}

	slog.Debug("metrics", "metrics", metrics)
	return metrics
}

func (m *Metrics) set(key bpfNfCounterKey, value uint64) error {
	keyType := bpfNfCounterType(key.Type)

	metric, exists := (*m)[keyType]
	if !exists {
		return fmt.Errorf("metric missing: %s", keyType.String())
	}

	ipVersion := fmt.Sprintf("IPv%d", key.IpVersion)
	ifName := tryResoveInterfaceName(int(key.Ifindex))
	labels := prometheus.Labels{
		NfCounterLabelIpVersion: ipVersion,
		NfCounterLabelInterface: ifName,
	}

	metric.With(labels).Set(float64(value))

	return nil
}

func tryResoveInterfaceName(ifindex int) string {
	iface, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return fmt.Sprintf("ifindex-%d", ifindex)
	}
	return iface.Name
}
