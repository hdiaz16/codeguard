package linters

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// DotnetVuln busca CVEs en las dependencias NuGet, que es un hueco real y
// medido: trivy NO detecta nada en un .csproj suelto —necesita un
// packages.lock.json, que la mayoría de los proyectos .NET no genera— así que
// hasta ahora un Newtonsoft.Json 9.0.1 con vulnerabilidad alta entraba al repo
// sin que ninguna capa dijera una palabra.
//
// La respuesta la da el propio NuGet (`dotnet list package --vulnerable`), que
// resuelve el grafo real de dependencias y consulta el índice de avisos de
// nuget.org: eso incluye las TRANSITIVAS, que son la mayoría de los CVEs que se
// heredan sin saberlo.
//
// El SDK de .NET es del desarrollador, no una herramienta que instalemos: si
// falta, el orquestador etiqueta la capa como "falta:" y no como degradada.
type DotnetVuln struct {
	// BlockCritical: true en CI (política §7, igual que trivy y govulncheck).
	// En local avisa: el índice de avisos puede haber cambiado hace minutos y
	// bloquear un commit por eso, sin que el código haya tocado la dependencia,
	// enseña a la gente a saltarse el hook.
	BlockCritical bool
	// SoloManifiestos: true en el camino del hook. Este comando SÍ restaura y
	// SÍ va a la red (medido: con un origen NuGet inalcanzable se queda
	// colgado minutos), así que en local sólo corre cuando cambian las
	// dependencias — el único momento en que la respuesta puede cambiar por
	// algo que hizo el desarrollador. El CI lo corre con cualquier .cs tocado.
	SoloManifiestos bool
	// Cache: mismos manifiestos = mismas dependencias. La clave lleva el día
	// UTC porque la respuesta depende del índice de avisos de ese día: un
	// acierto de ayer esconde los CVEs publicados hoy.
	Cache engines.Cache
}

func (DotnetVuln) Name() string { return "dotnet-vuln" }

// Applies responde "sí" también cuando el listado de proyectos falló: la
// interfaz no deja salir el error por aquí, y responder "no aplica" lo
// convertiría en una capa que no revisa nada sin dejar rastro. Se difiere a
// Run, que sí puede degradar el motor con el motivo.
func (e DotnetVuln) Applies(in engines.Input) bool {
	ps, err := e.proyectos(in)
	return err != nil || len(ps) > 0
}

// proyectos devuelve los .csproj cuyas dependencias hay que revisar por este
// cambio (rutas relativas a la raíz, separador /), ordenados.
func (e DotnetVuln) proyectos(in engines.Input) ([]string, error) {
	set := map[string]bool{}
	for _, f := range in.Files {
		if f.Status == "D" || dnbGenerado(f.Path) {
			continue
		}
		base := strings.ToLower(path.Base(f.Path))
		switch {
		case strings.HasSuffix(base, ".csproj"):
			set[f.Path] = true
		case base == "packages.lock.json":
			// Vive junto al .csproj: el proyecto es el de arriba.
			for _, p := range dnbCsprojDe(in.RepoRoot, f.Path) {
				set[p] = true
			}
		case base == "directory.packages.props" || base == "nuget.config":
			// Estos mandan HACIA ABAJO: con gestión centralizada de paquetes,
			// el Directory.Packages.props de la raíz fija la versión de todos
			// los proyectos del repo. Subir buscando un .csproj no encontraría
			// nada y el cambio que MÁS afecta a las dependencias quedaría sin
			// revisar, en silencio.
			//
			// Directory.Build.props queda FUERA a propósito: se toca por mil
			// razones que no son dependencias, y cada proyecto alcanzado cuesta
			// un restore contra la red. Barrer el repo entero por un cambio de
			// propiedades agotaría el plazo y degradaría la capa — que es otra
			// forma de no mirar. Sí entra en la clave de caché, para que el
			// resultado no sobreviva a un cambio que sí afecte.
			bajo, err := dnvCsprojBajo(in.RepoRoot, path.Dir(f.Path))
			if err != nil {
				return nil, err
			}
			for _, p := range bajo {
				set[p] = true
			}
		case !e.SoloManifiestos && strings.HasSuffix(base, ".cs"):
			for _, p := range dnbCsprojDe(in.RepoRoot, f.Path) {
				set[p] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// dnvCsprojBajo lista los .csproj RASTREADOS que cuelgan del directorio dado
// ("." = todo el repo).
func dnvCsprojBajo(repoRoot, dir string) ([]string, error) {
	rutas, err := gitdiff.Rastreados(repoRoot)
	if err != nil {
		// El nil silencioso aquí era fail-open: un fallo de git dejaba la capa
		// "limpia" sin mirar un solo proyecto, indistinguible de un repo sin
		// .csproj. "0 objetivos" y "no pude listar" tienen que separarse.
		return nil, err
	}
	prefijo := ""
	if dir != "." && dir != "" {
		prefijo = strings.TrimSuffix(dir, "/") + "/"
	}
	var out []string
	for _, r := range rutas {
		if prefijo != "" && !strings.HasPrefix(r, prefijo) {
			continue
		}
		if strings.EqualFold(path.Ext(r), ".csproj") && !dnbGenerado(r) {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ── la salida --format json ──────────────────────────────────────────────────
// Verificado con el SDK 10.0.204 sobre Newtonsoft.Json 9.0.1 y
// System.Text.Encodings.Web 4.5.0. Tres hechos que cambian el diseño:
//
//  1. Las vulnerabilidades traen "severity" y "advisoryurl" y NADA MÁS: no hay
//     campo con el identificador ni con la versión corregida. El GHSA sale del
//     último segmento de la URL, y la pista de arreglo no puede prometer una
//     versión concreta porque el comando no la dice.
//  2. Un proyecto LIMPIO se serializa exactamente igual que un proyecto que no
//     se pudo analizar: {"path": "..."} sin "frameworks". Lo único que los
//     distingue es el array "problems" — y el comando SALE CON CÓDIGO 0 en los
//     dos casos. Es la trampa de tipoFatal de semgrep otra vez: cero hallazgos
//     y "no pude mirar" se serializan igual y hay que separarlos a mano.
//  3. "transitivePackages" no trae requestedVersion (nadie la pidió: la
//     arrastra otra dependencia), y ahí es donde aparecen los CVEs heredados.
type dnvSalida struct {
	Problems []dnvProblema `json:"problems"`
	Projects []dnvProyecto `json:"projects"`
}

type dnvProblema struct {
	Project string `json:"project"`
	Level   string `json:"level"`
	Text    string `json:"text"`
}

type dnvProyecto struct {
	Path       string         `json:"path"`
	Frameworks []dnvFramework `json:"frameworks"`
}

type dnvFramework struct {
	Framework          string       `json:"framework"`
	TopLevelPackages   []dnvPaquete `json:"topLevelPackages"`
	TransitivePackages []dnvPaquete `json:"transitivePackages"`
}

type dnvPaquete struct {
	ID              string     `json:"id"`
	ResolvedVersion string     `json:"resolvedVersion"`
	Vulnerabilities []dnvAviso `json:"vulnerabilities"`
}

type dnvAviso struct {
	Severity    string `json:"severity"`
	AdvisoryURL string `json:"advisoryurl"`
}

func (e DotnetVuln) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	proys, err := e.proyectos(in)
	if err != nil {
		return nil, fmt.Errorf("no pude listar los .csproj rastreados: %w", err)
	}
	if len(proys) == 0 {
		return nil, nil
	}
	if _, err := exec.LookPath("dotnet"); err != nil {
		return nil, fmt.Errorf("SDK de .NET no disponible: %w", err)
	}
	var out []finding.Finding
	for _, proy := range proys {
		clave := ""
		if e.Cache != nil {
			if clave = e.claveProyecto(in.RepoRoot, proy); clave != "" {
				if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
					out = append(out, fs...)
					continue
				}
			}
		}
		fs, err := e.revisarProyecto(ctx, in.RepoRoot, proy)
		if err != nil {
			// Un proyecto que no se pudo consultar degrada el motor entero:
			// "0 CVE" con la mitad del repo sin mirar es peor que no dar dato.
			return nil, err
		}
		if e.Cache != nil && clave != "" {
			e.Cache.Guardar(map[string][]finding.Finding{clave: fs})
		}
		out = append(out, fs...)
	}
	return out, nil
}

// claveProyecto identifica una consulta: los manifiestos que determinan el
// grafo de dependencias (no los .cs: cambiar código no cambia qué paquetes
// resuelve NuGet) más el día UTC.
func (e DotnetVuln) claveProyecto(repoRoot, csproj string) string {
	dir := path.Dir(csproj)
	prefijo := ""
	if dir != "." {
		prefijo = dir + "/"
	}
	huella := engines.HuellaModulo(repoRoot, ".", func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		switch base {
		// Heredados: mandan sobre las versiones desde cualquier altura.
		case "directory.packages.props", "directory.build.props", "nuget.config", "global.json":
			return true
		}
		if prefijo != "" && !strings.HasPrefix(rel, prefijo) {
			return false
		}
		return base == "packages.lock.json" || strings.HasSuffix(base, ".csproj") ||
			strings.HasSuffix(base, ".props")
	})
	if huella == "" {
		return ""
	}
	return "dotnet-vuln:" + csproj + ":" + huella + ":" + time.Now().UTC().Format("2006-01-02")
}

func (e DotnetVuln) revisarProyecto(ctx context.Context, repoRoot, csproj string) ([]finding.Finding, error) {
	dirProy := filepath.Join(repoRoot, filepath.FromSlash(path.Dir(csproj)))
	cmd := exec.CommandContext(ctx, "dotnet", "list", path.Base(csproj), "package",
		"--vulnerable", "--include-transitive", "--format", "json")
	cmd.Dir = dirProy
	cmd.Env = proc.Entorno()
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	if salida.Recortada {
		return nil, fmt.Errorf("dotnet list package devolvió más de %d MB en %s", proc.MaxSalida>>20, csproj)
	}
	if runErr != nil {
		return nil, fmt.Errorf("dotnet list package no corrió en %s: %w%s", csproj, runErr, dnvDetalle(salida.Stderr))
	}
	return e.interpretar(salida.Stdout, repoRoot, csproj)
}

func (e DotnetVuln) interpretar(raw []byte, repoRoot, csproj string) ([]finding.Finding, error) {
	var s dnvSalida
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("salida de dotnet list package ilegible en %s: %v", csproj, err)
	}
	// Punto 2 del bloque de arriba: sin esto, un origen NuGet inalcanzable o un
	// restore fallido devolverían "0 CVE" con código de salida 0. Un motor de
	// seguridad que dice "limpio" cuando no pudo mirar es peor que no tenerlo.
	for _, p := range s.Problems {
		if strings.EqualFold(p.Level, "error") {
			return nil, fmt.Errorf("dotnet list package no pudo revisar %s: %s. "+
				"Corre `dotnet restore` y comprueba el acceso a los orígenes NuGet; "+
				"sin eso CodeGuard NO puede afirmar que las dependencias estén libres de CVEs",
				csproj, strings.TrimSpace(p.Text))
		}
	}
	if len(s.Projects) == 0 {
		return nil, fmt.Errorf("dotnet list package no devolvió ningún proyecto para %s: no se revisó nada", csproj)
	}

	// La línea del PackageReference hace el hallazgo navegable; si no aparece
	// (transitiva, o versión centralizada en otro archivo) se apunta a la 1 del
	// manifiesto, que es donde el desarrollador va a mirar de todos modos.
	lineas := dnvLineasDe(filepath.Join(repoRoot, filepath.FromSlash(csproj)))

	var out []finding.Finding
	vistos := map[string]bool{}
	for _, proy := range s.Projects {
		for _, fw := range proy.Frameworks {
			for _, pkg := range fw.TopLevelPackages {
				out = append(out, e.hallazgos(csproj, pkg, false, lineas, vistos)...)
			}
			for _, pkg := range fw.TransitivePackages {
				out = append(out, e.hallazgos(csproj, pkg, true, lineas, vistos)...)
			}
		}
	}
	return out, nil
}

// hallazgos traduce las vulnerabilidades de un paquete. La deduplicación es por
// paquete+versión+aviso: un proyecto multi-target repite el mismo CVE una vez
// por TFM, y el CVE es uno.
func (e DotnetVuln) hallazgos(csproj string, pkg dnvPaquete, transitiva bool, lineas map[string]int, vistos map[string]bool) []finding.Finding {
	var out []finding.Finding
	for _, av := range pkg.Vulnerabilities {
		id := dnvIdentificador(av.AdvisoryURL)
		clave := strings.ToLower(pkg.ID) + "@" + pkg.ResolvedVersion + "|" + id
		if vistos[clave] {
			continue
		}
		vistos[clave] = true

		grave := strings.EqualFold(av.Severity, "critical") || strings.EqualFold(av.Severity, "high")
		sev, bloquea := finding.Warning, false
		if grave {
			sev, bloquea = finding.Error, e.BlockCritical
		}
		origen := "declarada en este proyecto"
		pista := fmt.Sprintf("Sube %s por encima del rango afectado (`dotnet add package %s`); las versiones afectadas y la corregida están en %s.",
			pkg.ID, pkg.ID, av.AdvisoryURL)
		if transitiva {
			origen = "transitiva: la arrastra otra dependencia"
			pista = fmt.Sprintf("Es transitiva: sube el paquete que la arrastra, o fija una versión corregida con un PackageReference directo a %s. Detalle en %s.",
				pkg.ID, av.AdvisoryURL)
		}
		f := finding.Finding{
			Engine:   "dotnet-vuln",
			RuleKey:  id,
			Pillar:   finding.Security,
			Severity: sev,
			Blocking: bloquea,
			File:     csproj,
			Line:     lineas[strings.ToLower(pkg.ID)],
			Message: fmt.Sprintf("%s %s tiene una vulnerabilidad %s conocida (%s, %s): %s",
				pkg.ID, pkg.ResolvedVersion, strings.ToLower(av.Severity), id, origen, av.AdvisoryURL),
			Why: "Cadena de suministro (OWASP A03 2025). Lo resuelve NuGet sobre el grafo real de dependencias, " +
				"incluidas las transitivas: es el hueco que trivy no ve, porque sin packages.lock.json no encuentra nada en un .csproj.",
			FixHint:     pista,
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: pkg.ID + "@" + pkg.ResolvedVersion + " " + id,
		}
		if f.Line == 0 {
			f.Line = 1
		}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out
}

// dnvIdentificador saca el GHSA (o el CVE) del último segmento de la URL del
// aviso: el JSON no trae el identificador en ningún campo propio. Si la URL no
// tiene la forma esperada se usa la URL entera — un RuleKey feo es preferible a
// uno inventado, que además rompería el fingerprint de supresión.
func dnvIdentificador(url string) string {
	limpia := strings.TrimSuffix(strings.TrimSpace(url), "/")
	if limpia == "" {
		return "nuget-advisory"
	}
	seg := limpia[strings.LastIndex(limpia, "/")+1:]
	arriba := strings.ToUpper(seg)
	if strings.HasPrefix(arriba, "GHSA-") || strings.HasPrefix(arriba, "CVE-") {
		return seg
	}
	return limpia
}

var dnvIncluye = regexp.MustCompile(`(?i)Include\s*=\s*"([^"]+)"`)

// dnvLineasDe mapea id de paquete (en minúsculas) → línea de su
// PackageReference en el .csproj.
func dnvLineasDe(abs string) map[string]int {
	out := map[string]int{}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return out
	}
	for i, linea := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if !strings.Contains(linea, "PackageReference") {
			continue
		}
		for _, m := range dnvIncluye.FindAllStringSubmatch(linea, -1) {
			id := strings.ToLower(strings.TrimSpace(m[1]))
			if _, ya := out[id]; !ya {
				out[id] = i + 1
			}
		}
	}
	return out
}

func dnvDetalle(stderr []byte) string {
	s := strings.Join(strings.Fields(string(stderr)), " ")
	if s == "" {
		return ""
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return ": " + s
}
