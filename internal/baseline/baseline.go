// Package baseline lee y escribe .codeguard/baseline.txt: los fingerprints
// de hallazgos preexistentes (§17 paso 4). El archivo se versiona en el repo
// para que hook, daemon y CI supriman exactamente lo mismo.
package baseline

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/finding"
	"codeguard/internal/fsutil"
)

const RelPath = ".codeguard/baseline.txt"

// Load devuelve los fingerprints suprimidos. Sin archivo → mapa vacío y
// error nil. Un archivo que no se puede leer ENTERO es error, no un mapa
// parcial: devolver lo leído hasta el corte suprimiría sólo una parte de
// la deuda aceptada, y nadie sabría por qué unos hallazgos se suprimen y
// otros vuelven a bloquear.
func Load(repoRoot string) (map[string]bool, error) {
	f, err := os.Open(filepath.Join(repoRoot, filepath.FromSlash(RelPath)))
	if err != nil {
		// Solo "no existe" es el caso de mapa vacío. Permisos denegados, un
		// directorio en la ruta o un error de disco NO son "sin baseline": con
		// el nil,nil de antes, LoadOrWarn no tenía error que registrar y el
		// aviso que existe justo para esto no salía nunca — el equipo veía
		// bloquear de golpe toda la deuda aceptada sin una línea que lo dijera.
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, fmt.Errorf("baseline ilegible (%s): %w", RelPath, err)
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	// El buffer por defecto (64 KB) corta una línea larga con ErrTooLong y
	// Scan() lo disfraza de EOF: la baseline salía truncada sin ruido. Una
	// línea legítima aquí es un fingerprint hex + comentario humano, así
	// que 1 MB es holgura, no una invitación a abusar.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// formato: <fingerprint>  # comentario humano
		if i := strings.IndexByte(line, ' '); i > 0 {
			line = line[:i]
		}
		out[line] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("baseline ilegible (%s): %w", RelPath, err)
	}
	return out, nil
}

// LoadOrWarn es Load para los llamadores que no pueden propagar un error
// (literales de struct, condiciones de una línea). Ante una baseline
// ilegible degrada a "no hay supresiones" —fail-closed: más alertas, nunca
// suprimir de más— y LO DICE en el log en vez de fingir que no pasó nada.
// El nombre admite la degradación; quien pueda devolver error, use Load.
func LoadOrWarn(repoRoot string) map[string]bool {
	m, err := Load(repoRoot)
	if err != nil {
		log.Printf("baseline: %v — se ignora la baseline: nada se suprime en esta corrida", err)
		return nil
	}
	return m
}

// Write serializa la baseline con comentarios legibles para revisión en PR.
func Write(repoRoot string, findings []finding.Finding) (int, error) {
	seen := map[string]bool{}
	var lines []string
	for _, f := range findings {
		if f.Engine == "gitleaks" || f.Fingerprint == "" || seen[f.Fingerprint] {
			continue // los secretos jamás entran a la baseline
		}
		// El formato es un fingerprint por línea, así que un '\n' en cualquier
		// campo inyecta líneas —incluidos fingerprints ajenos— en el archivo
		// que hook, daemon y CI toman como verdad de supresión. En Windows el
		// nombre de archivo no puede traerlo, pero la clave de regla sí: la
		// ponen los motores desde la configuración del repo analizado. Y el
		// fingerprint tiene que ser un token limpio, porque al leer de vuelta
		// Load corta por el primer espacio y salta lo que empiece por '#'.
		// Se rechaza en vez de escapar: Load no podría des-escapar sin cambiar
		// un formato que está versionado. Abortar es la dirección segura —la
		// baseline no se regenera y los hallazgos siguen bloqueando.
		if strings.ContainsAny(f.Fingerprint+f.RuleKey+f.File, "\n\r") ||
			strings.ContainsAny(f.Fingerprint, " #") {
			return 0, fmt.Errorf("baseline: campos no serializables en hallazgo (regla %q, archivo %q)", f.RuleKey, f.File)
		}
		seen[f.Fingerprint] = true
		lines = append(lines, fmt.Sprintf("%s  # %s %s:%d", f.Fingerprint, f.RuleKey, f.File, f.Line))
	}
	sort.Strings(lines)

	path := filepath.Join(repoRoot, filepath.FromSlash(RelPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	header := "# CodeGuard baseline — hallazgos preexistentes suprimidos (§17 paso 4).\n" +
		"# Solo lo NUEVO bloquea. Regenerar con: codeguard baseline\n" +
		"# Los secretos nunca se suprimen.\n"
	content := header + strings.Join(lines, "\n") + "\n"
	// Atómico: la baseline se versiona y la leen hook, daemon y CI; un
	// archivo truncado por un crash a media escritura haría reaparecer la
	// deuda aceptada (o perderla) sin que nadie supiera por qué.
	if err := fsutil.EscribirAtomico(path, []byte(content), 0o644); err != nil {
		return 0, err
	}
	return len(lines), nil
}
