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
		// El constructor también devuelve nil cuando se NIEGA a armar un
		// cliente que mandaría la clave por HTTP en claro. Es el caso que el
		// usuario está configurando AHORA MISMO en esta pantalla, así que se
		// distingue del genérico "configuración incompleta" y se dice cómo
		// arreglarlo; sin esta rama, el cierre de seguridad se disfrazaría
		// de "revisa el endpoint", que manda a buscar donde no está el fallo.
		// Mismo orden que NewConClave, que mira el nombre del proveedor
		// (llm.go:181) ANTES del endpoint inseguro (llm.go:199): si el
		// diagnóstico los invirtiera, con las dos causas presentes nombraría la
		// que no cerró el cliente. Y el bool se descartaba, así que un typo caía
		// en el Proveedor de relleno —NecesitaKey en false— y el usuario recibía
		// "revisa el endpoint": el mismo síntoma de mandar a buscar donde no
		// está el fallo, con otro disfraz.
		prov, conocido := BuscarProveedor(cfg.Provider)
		if cfg.Provider != "" && !conocido {
			return "", fmt.Errorf("proveedor desconocido: %q. Revisa el nombre en la "+
				"configuración, o deja el proveedor vacío si el endpoint va escrito a mano",
				cfg.Provider)
		}
		if clave != "" && !endpointSeguroParaClave(cfg.Endpoint) {
			return "", fmt.Errorf("el endpoint %q no es HTTPS ni apunta a esta máquina: "+
				"no se envía la clave por HTTP en claro. Usa https:// o un modelo local "+
				"(Ollama, LM Studio)", cfg.Endpoint)
		}
		if (conocido && prov.NecesitaKey) || (cfg.Provider == "" && requiereKey(cfg, prov)) {
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
