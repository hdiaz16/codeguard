package attest

import (
	"fmt"
	"strings"
)

// NormalizeNewlines convierte todos los finales de línea CRLF o CR a LF estándar.
func NormalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

func isTrailerLine(line string) bool {
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return false
	}
	key := line[:idx]
	for i := 0; i < len(key); i++ {
		c := key[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func splitTrailer(line string) (string, string) {
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return "", ""
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
}

// ExtractTrailer extrae el valor del trailer CodeGuard-Attestation del mensaje de commit.
func ExtractTrailer(message string) (string, bool) {
	message = NormalizeNewlines(message)
	lines := strings.Split(message, "\n")

	// Descartar líneas vacías finales
	end := len(lines)
	for end > 0 && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	if end == 0 {
		return "", false
	}

	// Retroceder en el bloque contiguo de trailers
	start := end
	for start > 0 && isTrailerLine(lines[start-1]) {
		start--
	}
	if start == end {
		return "", false
	}

	var found string
	for i := start; i < end; i++ {
		k, v := splitTrailer(lines[i])
		if strings.EqualFold(k, TrailerKey) {
			found = v
		}
	}
	if found == "" {
		return "", false
	}
	return found, true
}

// InjectTrailer inserta o actualiza de forma idempotente el trailer CodeGuard-Attestation.
func InjectTrailer(message, value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("attest: el valor del trailer contiene saltos de línea prohibidos")
	}

	message = NormalizeNewlines(message)
	lines := strings.Split(message, "\n")

	// Descartar líneas vacías finales
	end := len(lines)
	for end > 0 && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}

	start := end
	for start > 0 && isTrailerLine(lines[start-1]) {
		start--
	}

	// Filtrar trailers previos de CodeGuard
	var cleanLines []string
	for i := 0; i < end; i++ {
		if i >= start {
			k, _ := splitTrailer(lines[i])
			if strings.EqualFold(k, TrailerKey) {
				continue
			}
		}
		cleanLines = append(cleanLines, lines[i])
	}

	trailerLine := fmt.Sprintf("%s: %s", TrailerKey, value)

	// Si había un bloque de trailers previo separado por línea en blanco
	if start > 0 && start < end && cleanLines[len(cleanLines)-1] != "" {
		cleanLines = append(cleanLines, trailerLine)
	} else if len(cleanLines) == 0 {
		cleanLines = append(cleanLines, trailerLine)
	} else {
		cleanLines = append(cleanLines, "", trailerLine)
	}

	return strings.Join(cleanLines, "\n") + "\n", nil
}
