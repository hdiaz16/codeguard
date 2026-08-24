package llm

import (
	"net"
	"net/url"
	"strings"

	"codeguard/internal/config"
)

func requiereKey(cfg config.LLM, prov Proveedor) bool {
	if cfg.Provider != "" {
		return prov.NecesitaKey
	}
	return !esLoopback(cfg.Endpoint)
}

func esLoopback(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Scheme == "unix" {
		return true
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func endpointSeguroParaClave(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return esLoopback(endpoint)
}

func normalizarEndpoint(bruto string) string {
	e := strings.TrimRight(strings.TrimSpace(bruto), "/")
	if e == "" {
		return e
	}
	bajo := strings.ToLower(e)
	esAzure := strings.Contains(bajo, ".services.ai.azure.com") ||
		strings.Contains(bajo, ".openai.azure.com") ||
		strings.Contains(bajo, ".cognitiveservices.azure.com")
	if !esAzure {
		return e
	}
	if strings.Contains(bajo, "/openai/") || strings.Contains(bajo, "?") {
		return e
	}
	return e + "/openai/v1"
}

func pistaDeError(cuerpo string) string {
	switch {
	case strings.Contains(cuerpo, "api-version"):
		return "\n\nEste endpoint de Azure es de la API clásica. Usa la moderna añadiendo " +
			"/openai/v1 al final del host (por ejemplo https://TU-RECURSO.services.ai.azure.com/openai/v1), " +
			"que es la que habla el dialecto de OpenAI sin api-version."
	case strings.Contains(cuerpo, "DeploymentNotFound"):
		return "\n\nEl modelo no existe en ese recurso: en Azure el nombre es el del DESPLIEGUE, " +
			"no el del modelo base."
	case strings.Contains(cuerpo, "401") || strings.Contains(cuerpo, "Unauthorized") ||
		strings.Contains(cuerpo, "invalid_api_key"):
		return "\n\nLa clave no es válida para este endpoint. Revisa que la variable de entorno " +
			"tenga la clave de ESTE recurso."
	}
	return ""
}
