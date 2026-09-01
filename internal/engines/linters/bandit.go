package linters

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/contrato"
	"codeguard/internal/finding"
	"codeguard/internal/fsutil"
	"codeguard/internal/gitdiff"
)

// Bandit adapta el analizador de seguridad AST de Python (bandit)
// al contrato engines.Engine (Pilar 4: Cobertura de Élite en Python).
type Bandit struct {
	Binary string
	Cache  engines.Cache
}

func (Bandit) Name() string { return "bandit" }

func (Bandit) Applies(in engines.Input) bool {
	return len(filesWithExt(in, ".py")) > 0
}

func (Bandit) Plan(in engines.Input) []engines.Unidad {
	archivos := filesWithExt(in, ".py")
	plan := make([]engines.Unidad, 0, len(archivos))
	for _, f := range archivos {
		plan = append(plan, engines.Unidad{Clase: "file", Ruta: f.Path})
	}
	return plan
}

type banditReport struct {
	Errors  []banditError  `json:"errors"`
	Results []banditResult `json:"results"`
}

type banditError struct {
	Filename string `json:"filename"`
	Reason   string `json:"reason"`
}

type banditResult struct {
	Code            string `json:"code"`
	Filename        string `json:"filename"`
	IssueConfidence string `json:"issue_confidence"`
	IssueCwe        struct {
		ID int `json:"id"`
	} `json:"issue_cwe"`
	IssueSeverity string `json:"issue_severity"`
	IssueText     string `json:"issue_text"`
	LineNumber    int    `json:"line_number"`
	TestID        string `json:"test_id"`
	TestName      string `json:"test_name"`
}

func (b Bandit) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	resultado, err := b.RunConCobertura(ctx, in)
	return resultado.Findings, err
}

// RunConCobertura conserva los hallazgos válidos aunque Bandit reporte que no
// pudo leer otro archivo. Antes `errors` se ignoraba: dos hallazgos en a.py más
// un error en b.py se convertían en «análisis exitoso» y, peor, b.py se
// cacheaba limpio. Los recibos hacen visible el hueco y sólo los archivos
// completamente revisados entran al caché.
func (b Bandit) RunConCobertura(ctx context.Context, in engines.Input) (engines.Resultado, error) {
	bin := b.Binary
	if bin == "" {
		bin = "bandit"
	}

	archivos := filesWithExt(in, ".py")
	if len(archivos) == 0 {
		return engines.Resultado{}, nil
	}

	var findings []finding.Finding
	var recibos []engines.Recibo
	pendientes := archivos
	if b.Cache != nil {
		claves := make(map[string]string, len(archivos))
		lista := make([]string, 0, len(archivos))
		for _, f := range archivos {
			if f.SHA256 == "" {
				continue
			}
			clave := claveBandit(f.Path, f.SHA256)
			claves[f.Path] = clave
			lista = append(lista, clave)
		}
		aciertos := b.Cache.Leer(lista)
		quedan := make([]gitdiff.ChangedFile, 0, len(archivos))
		for _, f := range archivos {
			clave, cacheable := claves[f.Path]
			fs, ok := aciertos[clave]
			if !cacheable || !ok {
				quedan = append(quedan, f)
				continue
			}
			findings = append(findings, fs...)
			recibos = append(recibos, reciboBandit(f.Path, engines.CoberturaCompleta, ""))
		}
		pendientes = quedan
	}
	if len(pendientes) == 0 {
		return engines.Resultado{Findings: findings, Recibos: recibos}, nil
	}

	var rutasRelativas []string
	for _, f := range pendientes {
		rutasRelativas = append(rutasRelativas, f.Path)
	}

	sanitizadas := fsutil.SanitizarRutas(in.RepoRoot, rutasRelativas)
	if len(sanitizadas) != len(rutasRelativas) {
		return engines.Resultado{}, fmt.Errorf("bandit: una o más rutas del diff salieron del repositorio")
	}

	args := []string{"-f", "json", "-q"}
	args = append(args, fsutil.ComoArgumentosCLI(sanitizadas)...)

	salida, fallo, err := runToolConSalida(ctx, "bandit", in.RepoRoot, bin, args...)
	if err != nil {
		return engines.Resultado{}, fmt.Errorf("bandit no corrió: %w", err)
	}

	nuevos, errores, parseErr := parseBanditJSON(salida, in.RepoRoot)
	if parseErr != nil {
		return engines.Resultado{}, parseErr
	}

	if len(nuevos) == 0 && len(errores) == 0 {
		if fallo {
			return engines.Resultado{}, fmt.Errorf("bandit salió con error y no produjo diagnósticos: %s", strings.TrimSpace(salida))
		}
		if err := contrato.Identidad(ctx, contrato.Version("bandit", bin, "--version",
			regexp.MustCompile(`(?i)bandit`),
			"Instala bandit con `pip install bandit` o `pipx install bandit`.",
		)); err != nil {
			return engines.Resultado{}, err
		}
	}

	completos, recibosNuevos := coberturaBandit(pendientes, nuevos, errores)
	recibos = append(recibos, recibosNuevos...)
	if b.Cache != nil {
		b.Cache.Guardar(porArchivoBandit(nuevos, completos, in.RepoRoot))
	}
	findings = append(findings, nuevos...)
	return engines.Resultado{Findings: findings, Recibos: recibos}, nil
}

func parseBanditJSON(raw, repoRoot string) ([]finding.Finding, []banditError, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "{}" {
		return nil, nil, nil
	}

	start := strings.Index(trimmed, "{")
	if start == -1 {
		return nil, nil, fmt.Errorf("bandit: salida no contiene JSON: %q", raw)
	}
	trimmed = trimmed[start:]

	var report banditReport
	if err := json.Unmarshal([]byte(trimmed), &report); err != nil {
		return nil, nil, fmt.Errorf("bandit: error al decodificar JSON: %w", err)
	}
	for i := range report.Errors {
		ruta := report.Errors[i].Filename
		if filepath.IsAbs(ruta) {
			if rel, err := filepath.Rel(repoRoot, ruta); err == nil {
				ruta = rel
			}
		}
		report.Errors[i].Filename = normalizarRutaBandit(ruta)
	}

	var findings []finding.Finding
	for _, res := range report.Results {
		relPath := res.Filename
		if filepath.IsAbs(relPath) {
			if rel, err := filepath.Rel(repoRoot, relPath); err == nil {
				relPath = rel
			}
		}
		relPath = normalizarRutaBandit(relPath)

		sev := finding.Warning
		blocking := false
		if strings.EqualFold(res.IssueSeverity, "high") {
			sev = finding.Error
			blocking = true
		} else if strings.EqualFold(res.IssueSeverity, "medium") {
			sev = finding.Warning
		} else {
			sev = finding.Info
		}

		cweStr := ""
		cweID := ""
		if res.IssueCwe.ID > 0 {
			cweID = fmt.Sprintf("%d", res.IssueCwe.ID)
			cweStr = fmt.Sprintf(" [CWE-%d]", res.IssueCwe.ID)
		}
		porQue, arreglo := retroalimentacionSeguridad("Bandit", res.TestID, cweID, res.IssueText)

		f := finding.Finding{
			Engine:   "bandit",
			RuleKey:  res.TestID,
			Pillar:   finding.Security,
			Severity: sev,
			Blocking: blocking,
			File:     relPath,
			Line:     res.LineNumber,
			EndLine:  res.LineNumber,
			Message:  res.IssueText + cweStr,
			Why:      porQue,
			FixHint:  arreglo,
			Source:   finding.Deterministic,
			// `res.Code` incluye números de línea. Usarlo como identidad hacía
			// cambiar la huella al insertar un comentario arriba del defecto.
			// El finalizador central lee la línea real del árbol analizado.
		}
		f.Normalizar()
		findings = append(findings, f)
	}

	return findings, report.Errors, nil
}

func normalizarRutaBandit(ruta string) string {
	ruta = filepath.ToSlash(filepath.Clean(ruta))
	return strings.TrimPrefix(ruta, "./")
}

func reciboBandit(ruta string, estado engines.EstadoCobertura, motivo string) engines.Recibo {
	return engines.Recibo{
		Unidad: engines.Unidad{Clase: "file", Ruta: ruta},
		Estado: estado,
		Motivo: motivo,
	}
}

func coberturaBandit(pendientes []gitdiff.ChangedFile, nuevos []finding.Finding, errores []banditError) ([]gitdiff.ChangedFile, []engines.Recibo) {
	porError := map[string]bool{}
	errorGlobal := false
	pendientePorRuta := map[string]bool{}
	for _, f := range pendientes {
		pendientePorRuta[normalizarRutaBandit(f.Path)] = true
	}
	for _, e := range errores {
		ruta := normalizarRutaBandit(e.Filename)
		if !pendientePorRuta[ruta] {
			errorGlobal = true
			continue
		}
		porError[ruta] = true
	}
	// Un diagnóstico que Bandit atribuye fuera del lote solicitado impide
	// demostrar qué archivo sí terminó. Se conservan los hallazgos, pero todos
	// los pendientes quedan parciales y ninguno se cachea limpio.
	for _, f := range nuevos {
		if !pendientePorRuta[normalizarRutaBandit(f.File)] {
			errorGlobal = true
		}
	}

	completos := make([]gitdiff.ChangedFile, 0, len(pendientes))
	recibos := make([]engines.Recibo, 0, len(pendientes))
	for _, f := range pendientes {
		estado, motivo := engines.CoberturaCompleta, ""
		if errorGlobal || porError[normalizarRutaBandit(f.Path)] {
			estado, motivo = engines.CoberturaParcial, "bandit-error"
		} else {
			completos = append(completos, f)
		}
		recibos = append(recibos, reciboBandit(f.Path, estado, motivo))
	}
	return completos, recibos
}

func claveBandit(ruta, sha string) string {
	// La ruta forma parte de la clave: aunque Bandit hoy no configura reglas por
	// patrón, preserva la identidad del finding y evita contaminar gemelos.
	return "bandit:" + normalizarRutaBandit(ruta) + ":" + sha
}

func porArchivoBandit(fs []finding.Finding, archivos []gitdiff.ChangedFile, repoRoot string) []engines.Cacheable {
	porRuta := make(map[string][]finding.Finding, len(archivos))
	for _, f := range fs {
		ruta := normalizarRutaBandit(f.File)
		f.File = ruta
		porRuta[ruta] = append(porRuta[ruta], f)
	}
	out := make([]engines.Cacheable, 0, len(archivos))
	for _, a := range archivos {
		if a.SHA256 == "" {
			continue
		}
		ruta := normalizarRutaBandit(a.Path)
		out = append(out, engines.Cacheable{
			Clave:    claveBandit(ruta, a.SHA256),
			Vigente:  engines.VigenciaDeArchivo(repoRoot, ruta, a.SHA256),
			Findings: porRuta[ruta],
		})
	}
	return out
}
