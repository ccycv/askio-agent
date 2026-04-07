package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/askio-cloud/askio-monitor/internal/agent"
	"github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/logging"
)

func main() {
	logger := logging.New()

	cmd := agent.NewCLI(agent.CLIOptions{Logger: logger})
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := cmd.ExecuteContext(ctx); err != nil {
		if errors.Is(err, config.ErrConfigNotFound) {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(2)
		}

		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
