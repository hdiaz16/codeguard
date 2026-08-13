package linters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// GoVet implementa la compuerta de lint de errores para Go (§7: lint severidad
// error BLOQUEA). Corre sobre los paquetes que contienen archivos tocados.
type GoVet struct {
	// Cache: mismo contenido del módulo y mismos paquetes pedidos = mismos
	// hallazgos. La clave es la del MÓDULO y no la del archivo porque `go vet`
	// typechequea el paquete entero: el veredicto sobre un archivo depende de
	// todos sus hermanos.
	//
	// Faltaba, y era el motor sin caché que más costaba: `go vet` compila los
	// paquetes tocados. En el repo de verificación tardaba 1,5 s en frío contra
	// los 4 ms de gofmt, y lo pagaba cada commit aunque no hubiera cambiado un
	// solo byte del módulo. staticcheck —que hace exactamente lo mismo, sobre
	// los mismos paquetes— sí lo tenía desde el principio.
	Cache engines.Cache
}

func (GoVet) Name() string { return "govet" }

func (GoVet) Applies(in engines.Input) bool {
	if len(filesWithExt(in, ".go")) == 0 {
		return false
	}
	_, err := os.Stat(filepath.Join(in.RepoRoot, "go.mod"))
	return err == nil
}

// formato: path.go:12:3: mensaje
var vetLine = regexp.MustCompile(`^(.+\.go):(\d+):(?:\d+:)?\s*(.+)$`)

func (e GoVet) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	pkgs := map[string]bool{}
	for _, f := range filesWithExt(in, ".go") {
		dir := filepath.Dir(filepath.FromSlash(f.Path))
		pkgs["./"+filepath.ToSlash(dir)] = true
	}
	// Ordenados: la lista entra en la clave del caché, y un orden de mapa haría
	// que la misma corrida produjera claves distintas cada vez — un caché que
	// nunca acierta y que además parece que funciona.
	paquetes := make([]string, 0, len(pkgs))
	for p := range pkgs {
		paquetes = append(paquetes, p)
	}
	sort.Strings(paquetes)

	clave := claveVet(in.RepoRoot, paquetes)
	if e.Cache != nil && clave != "" {
		if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
			return fs, nil
		}
	}

	args := append([]string{"vet"}, paquetes...)
	out, err := runTool(ctx, in.RepoRoot, "go", args...)
	if err != nil {
		return nil, fmt.Errorf("go vet no corrió: %w", err)
	}
	var findings []finding.Finding
	for _, line := range strings.Split(out, "\n") {
		m := vetLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		lineNo, _ := strconv.Atoi(m[2])
		f := finding.Finding{
			Engine:      "govet",
			RuleKey:     "govet",
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        filepath.ToSlash(m[1]),
			Line:        lineNo,
			Message:     m[3],
			Why:         "go vet solo reporta construcciones que son errores con alta certeza.",
			FixHint:     "Corrige el patrón señalado; go vet no produce falsos positivos intencionales.",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: m[3],
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}

	if e.Cache != nil && clave != "" {
		e.Cache.Guardar(map[string][]finding.Finding{clave: findings})
	}
	return findings, nil
}

// claveVet identifica un análisis: el contenido del módulo —todos sus .go y
// manifiestos rastreados, porque la compilación depende de todos y no sólo de
// los tocados— más los paquetes pedidos. Vacía = no cacheable.
//
// Es la misma clave que usa staticcheck, y por el mismo motivo: las dos
// herramientas typechequean paquetes enteros, así que cachear por archivo daría
// aciertos falsos en cuanto un hermano cambie.
func claveVet(repoRoot string, paquetes []string) string {
	huella := engines.HuellaModulo(repoRoot, ".", func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		return base == "go.mod" || base == "go.sum" || strings.HasSuffix(base, ".go")
	})
	if huella == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(huella + "|" + strings.Join(paquetes, ",")))
	return "govet:" + hex.EncodeToString(sum[:])
}
