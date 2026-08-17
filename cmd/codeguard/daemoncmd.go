package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/daemon"
	"codeguard/internal/ipc"
	"codeguard/internal/shadow"
	"codeguard/internal/store"
)

// daemonStopCmd apaga el daemon POR EL CAMINO BUENO: le pide por IPC que
// termine, que es lo mismo que el botón «Salir de CodeGuard» del menú.
//
// Existe para el desinstalador, que hasta ahora sólo podía matar el proceso
// con Stop-Process -Force — y un proceso fusilado no llega a quitar su icono
// de la bandeja. Windows deja el orbe fantasma pintado hasta que algo refresca
// el área de notificación, y en la bandeja nueva de Windows 11 lo único que la
// refresca es reiniciar Explorer, que no es cosa que un desinstalador deba
// hacerle a nadie. La salida limpia es no matar: pedir.
//
// Oculto porque su público es uninstall.ps1, no una persona; una persona tiene
// el menú de la bandeja. Sale 0 si el daemon murió (o si no estaba corriendo:
// apagar lo apagado no es un error) y 1 si sigue vivo tras el plazo — con eso
// el desinstalador sabe cuándo caer al taskkill de siempre.
func daemonStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "daemon-stop",
		Short:  "Pide al daemon que termine limpiamente (para el desinstalador)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Si el pipe no contesta, no hay daemon: nada que apagar.
			if _, err := ipc.Call(&ipc.Request{Command: "apagar", DeadlineMs: 2000}, 2*time.Second); err != nil {
				fmt.Println("el daemon no está corriendo")
				return nil
			}
			// El ack llega ANTES de que el proceso muera (el apagado va por el
			// hilo de la UI), así que se espera a que el pipe deje de contestar.
			for plazo := time.Now().Add(5 * time.Second); time.Now().Before(plazo); {
				time.Sleep(250 * time.Millisecond)
				if _, err := ipc.Call(&ipc.Request{Command: "ping", DeadlineMs: 500}, 500*time.Millisecond); err != nil {
					fmt.Println("daemon apagado")
					return nil
				}
			}
			return fmt.Errorf("el daemon sigue vivo tras pedirle el apagado")
		},
	}
}

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
