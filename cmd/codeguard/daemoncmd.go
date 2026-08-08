package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"codeguard/internal/daemon"
	"codeguard/internal/shadow"
	"codeguard/internal/store"
)

func daemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Arranca el daemon (servidor del pipe; la UI llega en F2.4)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			st, err := store.Open(store.DefaultPath())
			if err != nil {
				return err
			}
			defer st.Close()
			srv := &daemon.Server{Shadow: &shadow.Runner{Store: st}}
			return srv.Serve(ctx)
		},
	}
}
