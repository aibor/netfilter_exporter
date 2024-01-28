package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Config struct {
	interval time.Duration
	address  string
}

func run(ctx context.Context, config Config) error {
	metrics := newMetrics("netfilter")

	bpfState, err := bpfInit()
	if err != nil {
		return fmt.Errorf("bpf init: %v", err)
	}
	defer bpfState.Close()

	http.Handle("/metrics", promhttp.Handler())
	server := http.Server{
		Addr: config.address,
	}
	defer server.Close()

	go server.ListenAndServe()
	slog.Info("Server started. Stop with CTRL-C (SIGINT).")

	ticker := time.NewTicker(config.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			counters, err := bpfState.FetchCounters()
			if err != nil {
				return err
			}
			slog.Debug("fetched counters", "counters", counters)

			for key, value := range counters {
				keyType := bpfNfCounterType(key.Type)
				slog.Debug("process counter", "type", keyType)

				if err := metrics.set(key, value); err != nil {
					slog.Error("set metric", "error", err)
				}
			}

		}
	}
}

func main() {
	fsName := fmt.Sprintf("%s [flags...]", os.Args[0])
	fs := flag.NewFlagSet(fsName, flag.ExitOnError)

	var config Config
	fs.DurationVar(
		&config.interval,
		"interval",
		15*time.Second,
		"metric fetch interval",
	)
	fs.StringVar(
		&config.address,
		"address",
		"localhost:8000",
		"HTTP server address",
	)

	var logConfig LogConfig
	fs.BoolVar(
		&logConfig.debug,
		"log.debug",
		false,
		"enable debug log output",
	)
	fs.BoolVar(
		&logConfig.silent,
		"log.silent",
		false,
		"disable info log output",
	)
	fs.BoolVar(
		&logConfig.json,
		"log.json",
		false,
		"log JSON formatted",
	)

	fs.Parse(os.Args[1:])

	setLogging(logConfig)

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP,
	)
	defer cancel()

	if err := run(ctx, config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
