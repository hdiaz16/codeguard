package llm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"codeguard/internal/config"
)

// Probar hace una llamada real y mínima al modelo configurado. Una pantalla
// —o un comando— que sólo guarda deja al desarrollador descubrir el error en
// su siguiente commit, cuando ya no está pensando en esto.
//
// clavePegada permite probar una clave que aún no está guardada, que es el
// caso normal cuando alguien acaba de escribirla en el formulario.
func Probar(cfg config.LLM, clavePegada string) (string, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return "", fmt.Errorf("falta el endpoint")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return "", fmt.Errorf("falta el modelo")
	}

	// La clave pegada gana sobre lo guardado, y se pasa explícita en vez de
	// inyectarla un momento en el entorno del proceso como se hacía antes.
	// Aquel truco dejó de funcionar en cuanto la clave pasó a leerse de la
	// bóveda: se habría probado la GUARDADA en vez de la que el usuario acaba
	// de escribir, y un "OK" así es peor que un error, porque manda a cerrar el
	// formulario creyendo que ya está.
	clave := clavePegada
	if clave == "" {
		clave = ClaveDe(cfg)
	}
	c := NewConClave(cfg, clave)
	if c == nil {
		prov, _ := BuscarProveedor(cfg.Provider)
		if prov.NecesitaKey || cfg.Provider == "" {
			nombre := cfg.APIKeyEnv
			if nombre == "" {
				nombre = "(ninguna variable configurada)"
			}
			return "", fmt.Errorf("falta la clave: %s no tiene valor", nombre)
		}
		return "", fmt.Errorf("configuración incompleta: revisa el endpoint")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	inicio := time.Now()
	res, err := c.Complete(ctx, cfg.Model,
		"Responde solo con JSON.",
		`Devuelve exactamente {"ok":true} y nada mas.`,
		40*time.Second, 64)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("respondió en %d ms · %d tokens · dialecto %s",
		time.Since(inicio).Milliseconds(),
		res.Usage.PromptTokens+res.Usage.CompletionTokens,
		c.Dialecto()), nil
}
