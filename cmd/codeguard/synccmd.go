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
	cmd := &cobra.Command{
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
			// (el outbox lo recuerda por evento y el siguiente intento sigue).
			fmt.Printf("telemetría central: %d fila(s) empujada(s)\n", res.Total())
			fmt.Printf("  repos      %d\n", res.Repos)
			fmt.Printf("  runs       %d\n", res.Runs)
			fmt.Printf("  findings   %d\n", res.Findings)
			fmt.Printf("  feedback   %d\n", res.Feedback)
			fmt.Printf("  llm_calls  %d\n", res.LLMCalls)
			if n, e := st.EnCuarentena(); e == nil && n > 0 {
				fmt.Printf("\n⚠️  %d evento(s) EN CUARENTENA no viajan (un error permanente). "+
					"Revísalos: `codeguard sync cuarentena`\n", n)
			}
			return err
		},
	}
	cmd.AddCommand(syncCuarentenaCmd(), syncRetryCmd(), syncDiscardCmd())
	return cmd
}

// syncCuarentenaCmd lista los eventos en cuarentena con su causa: telemetría
// que no viaja porque el central la rechazó de forma permanente.
func syncCuarentenaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cuarentena",
		Short: "Lista los eventos de sync en cuarentena (no viajan al central) y por qué",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(store.DefaultPath())
			if err != nil {
				return err
			}
			defer st.Close()
			evs, err := st.ListarCuarentena()
			if err != nil {
				return err
			}
			if len(evs) == 0 {
				fmt.Println("no hay eventos en cuarentena: toda la telemetría viaja o está en reintento.")
				return nil
			}
			fmt.Printf("%d evento(s) en cuarentena:\n", len(evs))
			for _, e := range evs {
				fmt.Printf("  seq %d  [%s] %s/%s  — %s\n", e.Seq, e.ErrorClass, e.Entity, e.RowID, e.ErrorDetail)
			}
			fmt.Println("\nResuelve el problema y `codeguard sync retry <seq>`, o `codeguard sync discard <seq> --reason ...`")
			return nil
		},
	}
}

func syncRetryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "retry <seq>",
		Short: "Reintenta un evento en cuarentena (tras resolver la causa)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			seq, err := parseSeq(args[0])
			if err != nil {
				return err
			}
			st, err := store.Open(store.DefaultPath())
			if err != nil {
				return err
			}
			defer st.Close()
			if err := st.ReintentarCuarentena(seq); err != nil {
				return err
			}
			fmt.Printf("evento %d vuelto a pending: viajará en el próximo sync\n", seq)
			return nil
		},
	}
}

func syncDiscardCmd() *cobra.Command {
	var razon string
	c := &cobra.Command{
		Use:   "discard <seq> --reason <motivo>",
		Short: "Descarta un evento en cuarentena a propósito (queda auditado)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if razon == "" {
				return fmt.Errorf("--reason es obligatorio: descartar telemetría queda auditado y sin motivo no se hace")
			}
			seq, err := parseSeq(args[0])
			if err != nil {
				return err
			}
			st, err := store.Open(store.DefaultPath())
			if err != nil {
				return err
			}
			defer st.Close()
			if err := st.DescartarCuarentena(seq, razon); err != nil {
				return err
			}
			fmt.Printf("evento %d descartado (%s): no se empujará\n", seq, razon)
			return nil
		},
	}
	c.Flags().StringVar(&razon, "reason", "", "motivo del descarte (obligatorio, queda auditado)")
	return c
}

func parseSeq(s string) (int64, error) {
	var seq int64
	if _, err := fmt.Sscanf(s, "%d", &seq); err != nil || seq <= 0 {
		return 0, fmt.Errorf("seq inválido: %q (debe ser un número positivo)", s)
	}
	return seq, nil
}
