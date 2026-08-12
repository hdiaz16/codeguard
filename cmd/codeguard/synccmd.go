package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/store"
)

func syncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Empuja la telemetría local al Postgres central (precisión y bypass a nivel organización)",
		RunE: func(cmd *cobra.Command, args []string) error {
			dsn := os.Getenv(store.EnvTelemetriaDSN)
			if dsn == "" {
				// Sin DSN no hay central: se dice claro y se sale bien. Es la
				// configuración normal de una máquina fuera de la organización.
				fmt.Printf("telemetría central sin configurar: define %s con el DSN del Postgres central\n", store.EnvTelemetriaDSN)
				fmt.Println("(es un secreto con contraseña: va en el entorno, nunca en el config del repo)")
				return nil
			}
			st, err := store.Open(store.DefaultPath())
			if err != nil {
				return err
			}
			defer st.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			res, err := st.SyncCentral(ctx, dsn)
			// El resumen se imprime aunque haya error: lo que ya viajó, viajó
			// (la marca lo recuerda y el siguiente intento sigue desde ahí).
			fmt.Printf("telemetría central: %d fila(s) empujada(s)\n", res.Total())
			fmt.Printf("  repos      %d\n", res.Repos)
			fmt.Printf("  runs       %d\n", res.Runs)
			fmt.Printf("  findings   %d\n", res.Findings)
			fmt.Printf("  feedback   %d\n", res.Feedback)
			fmt.Printf("  llm_calls  %d\n", res.LLMCalls)
			return err
		},
	}
}
