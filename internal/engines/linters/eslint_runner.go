package linters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
	"codeguard/internal/textutil"
)

func correrLinterJS(ctx context.Context, repoRoot, dir string, tool herramienta, rutas []string) ([]finding.Finding, error) {
	abs := filepath.Join(repoRoot, filepath.FromSlash(dir))
	bin, args := binarioJS(abs, tool)

	if tool == hBiome {
		args = append(args, "check", "--reporter=json")
	} else {
		// --no-error-on-unmatched-pattern: sin esto, UN archivo que desapareció
		// entre el diff y el análisis hace salir a eslint con 2 y se pierde el
		// lote completo. Verificado en eslint 8.57 y 10.8: ambos lo aceptan.
		//
		// Lo que NO se pasa es --no-warn-ignored, y esa ausencia es empírica:
		// eslint 8.57 lo rechaza ("Invalid option '--warn-ignored'") y sale con
		// 2, así que pasarlo convertiría en fallo duro todos los repos que aún
		// van con eslint 8 y .eslintrc — que son muchos. Los avisos de archivo
		// ignorado se filtran al parsear, que funciona con cualquier versión.
		args = append(args, "--format", "json", "--no-error-on-unmatched-pattern")
	}
	args = append(args, rutas...)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = abs
	cmd.Env = proc.EntornoDePerfil(proc.PerfilNode)
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)

	// Se lee stdout SOLO, nunca la salida combinada: biome escribe en stderr
	// "The `json` and `json-pretty` reporters are experimental…" más su barra de
	// progreso, y pegar eso al JSON lo vuelve imparseable. El stderr se guarda
	// para poder explicar los fallos.
	out := bytes.TrimSpace(salida.Stdout)
	motivo := diagnosticoJS(salida.Stderr, salida.Stdout)

	if salida.Recortada {
		return nil, fmt.Errorf("%s devolvió más de %d MB en %s: el JSON llega a medias y no se puede parsear", tool, proc.MaxSalida>>20, dir)
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		// No arrancó: binario ausente, permisos, plazo agotado. El orquestador lo
		// etiqueta "falta:" — eslint y biome son dependencias DEL PROYECTO, no
		// herramientas nuestras, así que no hay nada que instalemos por él.
		return nil, fmt.Errorf("%s no corrió en %s: %w", tool, dir, runErr)
	}
	codigo := 0
	if exitErr != nil {
		codigo = exitErr.ExitCode()
	}

	// Aquí está la distinción que importa: salir con 1 es la forma NORMAL de
	// decir "encontré problemas" —como semgrep— y su JSON es válido y completo.
	// eslint reserva el 2 para el fallo real (config ilegible, opción inválida) y
	// entonces no escribe JSON en absoluto, sino un "Oops! Something went wrong!"
	// en stderr. Confundir los dos casos significaría, en un sentido, ignorar
	// hallazgos legítimos y, en el otro, anunciar "0 problemas" cuando el linter
	// ni arrancó.
	if tool == hESLint && codigo >= 2 {
		return nil, fmt.Errorf("eslint falló en %s (código %d): %s", dir, codigo, motivo)
	}
	// biome no documenta un código dedicado al fallo real: su config rota también
	// sale con 1, pero sin nada en stdout. La ausencia de JSON es la señal fiable
	// para las dos herramientas, y cubre el caso en que eslint cambie de códigos.
	if len(out) == 0 {
		return nil, fmt.Errorf("%s no dejó salida analizable en %s (código %d): %s", tool, dir, codigo, motivo)
	}

	if tool == hBiome {
		return hallazgosBiome(repoRoot, dir, out)
	}
	return hallazgosESLint(repoRoot, dir, out)
}

// diagnosticoJS elige el texto con el que explicarle al dev por qué no hubo
// análisis. stderr primero: es donde las dos herramientas ponen el motivo real.
func diagnosticoJS(stderr, stdout []byte) string {
	txt := strings.TrimSpace(string(stderr))
	if txt == "" {
		txt = strings.TrimSpace(string(stdout))
	}
	if txt == "" {
		return "sin salida"
	}
	return truncarJS(colapsar(txt), 400)
}

// colapsar aplasta el texto a una línea: las dos herramientas adornan sus
// errores con barras de progreso y marcos de caracteres que en una sola línea
// del informe no aportan nada.
func colapsar(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func truncarJS(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// TruncarRunas evita partir una runa UTF-8 en el byte n (mojibake).
	return textutil.TruncarRunas(s, n) + "…"
}

// ── eslint ──────────────────────────────────────────────────────────────────

type eslintArchivo struct {
	FilePath string          `json:"filePath"`
	Messages []eslintMensaje `json:"messages"`
}

type eslintMensaje struct {
	// RuleID es null en los mensajes que no vienen de una regla: los errores de
	// parseo y los avisos sobre el archivo (ignorado, sin config que lo cubra).
	// Por eso es puntero y no string.
	RuleID   *string `json:"ruleId"`
	Severity int     `json:"severity"`
	Message  string  `json:"message"`
	Line     int     `json:"line"`
	EndLine  int     `json:"endLine"`
	Fatal    bool    `json:"fatal"`
	// Fix presente = `eslint --fix` lo arregla solo. Distinto de Suggestions,
	// que --fix NO aplica porque exigen que alguien elija.
	Fix         *json.RawMessage  `json:"fix"`
	Suggestions []json.RawMessage `json:"suggestions"`
}

// porQueESLint: el dev tiene que entender que esto no es una regla nuestra.
const porQueESLint = "Es la configuración de lint DEL PROPIO REPO (eslint.config/.eslintrc), no una regla de CodeGuard: el CI la aplicará igual."

func hallazgosESLint(repoRoot, dir string, raw []byte) ([]finding.Finding, error) {
	var archivos []eslintArchivo
	if err := json.Unmarshal(raw, &archivos); err != nil {
		return nil, fmt.Errorf("salida de eslint ilegible en %s: %v", dir, err)
	}
	var findings []finding.Finding
	for _, a := range archivos {
		file := rutaRepoJS(repoRoot, dir, a.FilePath)
		enPry := enProyecto(dir, file)
		for _, m := range a.Messages {
			regla := ""
			if m.RuleID != nil {
				regla = *m.RuleID
			}
			// Sin regla y sin ser fatal, el mensaje habla DEL ARCHIVO, no del
			// código: "File ignored because of a matching ignore pattern" o
			// "File ignored because no matching configuration was supplied".
			// El segundo salta en cuanto se le pasa un .ts a una config que sólo
			// cubre .js —lo normal— y convertirlo en hallazgo llenaría el informe
			// de avisos sobre archivos que el repo decidió no lintar.
			if regla == "" && !m.Fatal {
				continue
			}
			sev := finding.Warning
			if m.Severity >= 2 {
				sev = finding.Error
			}
			mensaje := m.Message
			fix := "Revisa la regla " + regla + " en la configuración de lint del repo."
			switch {
			case regla == "":
				// Error de parseo: eslint no pudo ni leer el archivo. Se reporta
				// como error porque el CI dirá lo mismo, pero el consejo apunta al
				// otro motivo posible: que el parser del repo no cubra este tipo
				// de archivo.
				regla = "parsing-error"
				fix = "Corrige la sintaxis señalada; si el archivo es válido, la config de eslint no tiene parser para este tipo de archivo."
			case m.Fix != nil:
				fix = "Auto-corregible: " + comandoJS(dir, "npx eslint --fix", enPry) + "."
			case len(m.Suggestions) > 0:
				// Precisión deliberada: `--fix` no las aplica. Prometer lo
				// contrario haría que el dev lo ejecutara, viera que nada cambia y
				// dejara de creerse los FixHint.
				fix = "Hay que corregirlo a mano: la regla " + regla + " sólo ofrece sugerencias, y `--fix` no las aplica."
			}
			f := finding.Finding{
				Engine:  string(hESLint),
				RuleKey: regla,
				Pillar:  finding.Quality,
				// Política §7: lint de severidad error BLOQUEA, igual que govet.
				// severity 1 (warn) avisa: es lo que el repo marcó como "quiero
				// verlo, no quiero que me pare".
				Severity: sev,
				Blocking: sev == finding.Error,
				File:     file,
				Line:     maxLinea(m.Line),
				EndLine:  m.EndLine,
				Message:  mensaje,
				Why:      porQueESLint,
				FixHint:  fix,
				Verified: true,
				Source:   finding.Deterministic,
			}
			findings = append(findings, f)
		}
	}
	return findings, nil
}
