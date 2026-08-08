package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"codeguard/internal/daemon"
)

func daemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Arranca el daemon (servidor del pipe; la UI llega en F2.4)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			srv := &daemon.Server{}
			return srv.Serve(ctx)
		},
	}
}
