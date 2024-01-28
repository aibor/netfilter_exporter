package main

import (
	"log/slog"
	"os"
)

type LogConfig struct {
	debug  bool
	silent bool
	json   bool
}

func setLogging(config LogConfig) {
	logOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	if config.debug {
		logOpts.Level = slog.LevelDebug
	} else if config.silent {
		logOpts.Level = slog.LevelWarn
	}

	var handler slog.Handler
	if config.json {
		handler = slog.NewJSONHandler(os.Stderr, logOpts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, logOpts)
	}

	slog.SetDefault(slog.New(handler))
}
