// Package baseline lee y escribe .codeguard/baseline.txt: los fingerprints
// de hallazgos preexistentes (§17 paso 4). El archivo se versiona en el repo
// para que hook, daemon y CI supriman exactamente lo mismo.
package baseline

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/finding"
)

const RelPath = ".codeguard/baseline.txt"

// Load devuelve los fingerprints suprimidos. Sin archivo → mapa vacío.
func Load(repoRoot string) map[string]bool {
	f, err := os.Open(filepath.Join(repoRoot, filepath.FromSlash(RelPath)))
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
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
	return out
}

// Write serializa la baseline con comentarios legibles para revisión en PR.
func Write(repoRoot string, findings []finding.Finding) (int, error) {
	seen := map[string]bool{}
	var lines []string
	for _, f := range findings {
		if f.Engine == "gitleaks" || f.Fingerprint == "" || seen[f.Fingerprint] {
			continue // los secretos jamás entran a la baseline
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
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return 0, err
	}
	return len(lines), nil
}
