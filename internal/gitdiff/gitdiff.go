// Package gitdiff lee el conjunto de archivos cambiados y el diff unificado,
// con las normalizaciones de paridad de la sección 4.1 de la spec.
package gitdiff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"

	"codeguard/internal/engines/proc"
	"path/filepath"
	"strings"
)

type ChangedFile struct {
	Path   string // relativo a la raíz del repo, separador /
	Status string // A, M, D, R...
	SHA256 string // del contenido normalizado a LF; vacío si el archivo fue borrado
}

type Diff struct {
	Files   []ChangedFile
	Unified string // diff completo normalizado a LF
	Lines   int    // líneas de diff (aprox: añadidas + eliminadas)
}

func run(repoRoot string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	proc.SinVentana(cmd)
	cmd.Dir = repoRoot
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, errb.String())
	}
	return out.Bytes(), nil
}

func normalizeLF(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

// Range lee el diff base..head (modo ci).
func Range(repoRoot, base, head string) (*Diff, error) {
	return read(repoRoot, []string{base + ".." + head})
}

// Staged lee el diff del índice (modo hook, fase 2).
func Staged(repoRoot string) (*Diff, error) {
	return read(repoRoot, []string{"--cached"})
}

func read(repoRoot string, rangeArgs []string) (*Diff, error) {
	// --no-textconv --no-ext-diff: paridad del hash entre máquinas (sección 4.1).
	common := append([]string{"diff", "--no-textconv", "--no-ext-diff", "--no-color"}, rangeArgs...)

	nameStatus, err := run(repoRoot, append(common, "--name-status")...)
	if err != nil {
		return nil, err
	}
	unified, err := run(repoRoot, append(common, "--unified=3")...)
	if err != nil {
		return nil, err
	}
	unifiedLF := normalizeLF(unified)

	d := &Diff{Unified: string(unifiedLF)}
	for _, line := range strings.Split(strings.TrimSpace(string(nameStatus)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		status := parts[0][:1]
		path := parts[len(parts)-1] // en renames (R100\told\tnew) el destino es el último campo
		cf := ChangedFile{Path: filepath.ToSlash(path), Status: status}
		if status != "D" {
			if raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(path))); err == nil {
				sum := sha256.Sum256(normalizeLF(raw))
				cf.SHA256 = hex.EncodeToString(sum[:])
			}
		}
		d.Files = append(d.Files, cf)
	}
	for _, l := range strings.Split(d.Unified, "\n") {
		if len(l) > 0 && (l[0] == '+' || l[0] == '-') && !strings.HasPrefix(l, "+++") && !strings.HasPrefix(l, "---") {
			d.Lines++
		}
	}
	return d, nil
}

// RepoRoot devuelve la raíz del repo que contiene dir.
func RepoRoot(dir string) (string, error) {
	out, err := run(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
