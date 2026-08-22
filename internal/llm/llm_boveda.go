package llm

import (
	"fmt"
	"log"
	"os"
	"sync"

	"codeguard/internal/config"
	"codeguard/internal/secreto"
)

var leerSecreto = secreto.Leer

func ClaveDe(cfg config.LLM) string {
	if cfg.APIKeyEnv == "" {
		return ""
	}
	guardada, err := leerSecreto(cfg.APIKeyEnv)
	clave, aviso := decidirClave(cfg.APIKeyEnv, guardada, err, os.Getenv(cfg.APIKeyEnv))
	avisarDeLaBoveda(aviso)
	return clave
}

func decidirClave(nombreVar, guardada string, errBoveda error, delEntorno string) (clave, aviso string) {
	switch {
	case errBoveda == nil && guardada != "":
		return guardada, ""
	case errBoveda == nil || secreto.NoEncontrado(errBoveda):
		return delEntorno, ""
	}
	if delEntorno != "" {
		return delEntorno, fmt.Sprintf("la bóveda no pudo leer %s (%v). Se usó el valor de la "+
			"variable de entorno, así que la capa sigue en pie, pero la clave GUARDADA no se está "+
			"leyendo: revisa el Administrador de credenciales", nombreVar, errBoveda)
	}
	return "", fmt.Sprintf("la bóveda no pudo leer %s (%v) y la variable de entorno tampoco tiene "+
		"valor: la capa de consejo queda apagada por un FALLO de la bóveda, no porque falte "+
		"configurar la clave", nombreVar, errBoveda)
}

var (
	muAviso     sync.Mutex
	ultimoAviso string
)

func avisarDeLaBoveda(aviso string) {
	muAviso.Lock()
	repetido := aviso == ultimoAviso
	ultimoAviso = aviso
	muAviso.Unlock()
	if aviso != "" && !repetido {
		log.Printf("clave del modelo: %s", aviso)
	}
}
