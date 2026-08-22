package staticcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/textutil"
)

func claveModulo(repoRoot, dir string, paquetes []string, idBinario string) string {
	if idBinario == "" {
		return ""
	}
	huella := engines.HuellaModulo(repoRoot, dir, func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		// staticcheck.conf entra como un manifiesto más: decide QUÉ
		// comprobaciones corren, así que el mismo código con otra config es
		// otro análisis. Sin él en la huella, activar o desactivar una
		// comprobación no invalidaba nada y el caché seguía sirviendo el
		// resultado de la configuración anterior.
		return base == "go.mod" || base == "go.sum" || base == "staticcheck.conf" ||
			strings.HasSuffix(base, ".go")
	})
	if huella == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(huella + "|" + idBinario + "|" + strings.Join(paquetes, ",")))
	return "staticcheck:" + hex.EncodeToString(sum[:])
}

// diceSerStaticcheck reconoce la respuesta de `staticcheck -version`. En esta
// máquina: "staticcheck.exe 2026.1 (v0.7.0)".
//
// Vale por CUALQUIERA de las dos marcas, y no por las dos, porque cada una cubre
// un caso legítimo que la otra rechazaría: un binario renombrado imprime el
// nombre que tenga (pero sí trae el "(v…" del módulo), y una compilación de
// desarrollo no trae número de versión (pero sí dice staticcheck). Lo que ninguna
// de las dos deja pasar es a un impostor con el nombre correcto, que es el fallo
// que de verdad ocurrió —`npx --no-install tsc` resolviendo a un paquete que no
// es TypeScript— ni el silencio absoluto.
var diceSerStaticcheck = regexp.MustCompile(`(?i)staticcheck|\(v\d`)

func interpretar(raw []byte, dir string, bases ...string) ([]finding.Finding, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var out []finding.Finding
	for {
		var p problema
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("salida de staticcheck ilegible: %v", err)
		}
		// El paquete no compila: sin programa no hay SSA que analizar. No es
		// un hallazgo sino análisis imposible — se degrada el motor con el
		// detalle, y el error real ya lo habrán señalado gofmt o govet.
		if p.Code == "compile" {
			return nil, fmt.Errorf("staticcheck no pudo compilar %s: %s", dir, recorte([]byte(p.Message)))
		}
		var sev finding.Severity
		var bloquea bool
		switch p.Severity {
		case "error":
			// Política §7: lint de severidad error bloquea, como govet.
			sev, bloquea = finding.Error, true
		case "ignored":
			// Suprimido con //lint:ignore en el propio código: se respeta.
			continue
		default:
			// "warning" (y cualquier severidad futura): avisa sin bloquear.
			sev, bloquea = finding.Warning, false
		}
		f := finding.Finding{
			Engine:      "staticcheck",
			RuleKey:     p.Code,
			Pillar:      finding.Quality,
			Severity:    sev,
			Blocking:    bloquea,
			File:        relativizar(p.Location.File, bases, dir),
			Line:        p.Location.Line,
			Message:     p.Message,
			Why:         fmt.Sprintf("staticcheck (%s) analiza la forma SSA del programa: el bug se demuestra sobre el flujo real de valores, no por parecido textual.", p.Code),
			FixHint:     fmt.Sprintf("Corrige lo que señala el mensaje; la ficha completa de la regla está en https://staticcheck.dev/docs/checks#%s.", p.Code),
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: p.Message,
		}
		if p.End.Line > p.Location.Line {
			f.EndLine = p.End.Line
		}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out, nil
}

// relativizar convierte el path absoluto que reporta staticcheck en uno
// relativo a la raíz del repo con separador /: se recorta el directorio del
// módulo probando cada base (comparando sin distinguir mayúsculas, que es
// como comparan los paths de Windows) y se antepone el módulo cuando no es
// la raíz. Un path absoluto que no cuelga de ninguna base se deja tal cual:
// mejor uno raro que uno inventado.
func relativizar(file string, bases []string, dir string) string {
	f := filepath.ToSlash(file)
	recortado := false
	for _, b := range bases {
		base := filepath.ToSlash(b)
		if base != "" && len(f) > len(base)+1 && f[len(base)] == '/' &&
			strings.EqualFold(f[:len(base)], base) {
			f, recortado = f[len(base)+1:], true
			break
		}
	}
	if !recortado && (path.IsAbs(f) || filepath.IsAbs(filepath.FromSlash(f)) || (len(f) > 1 && f[1] == ':')) {
		return f
	}
	if dir != "." {
		return path.Join(dir, f)
	}
	return f
}

func recorte(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 300 {
		s = textutil.TruncarRunas(s, 300) + "…"
	}
	return s
}
