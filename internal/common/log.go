package common

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

func NewLogger(level string) *slog.Logger {
	var parsed slog.Level
	switch strings.ToUpper(level) {
	case "DEBUG":
		parsed = slog.LevelDebug
	case "WARN":
		parsed = slog.LevelWarn
	case "ERROR":
		parsed = slog.LevelError
	default:
		parsed = slog.LevelInfo
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parsed,
	}))
}

func WithRequestID(ctx context.Context, logger *slog.Logger, requestID string) *slog.Logger {
	if requestID == "" {
		return logger
	}
	return logger.With("request_id", requestID)
}
