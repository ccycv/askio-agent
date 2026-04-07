package logging

import (
	"log/slog"
	"os"
)

// New returns a default structured logger.
func New() *slog.Logger {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	return slog.New(h)
}
