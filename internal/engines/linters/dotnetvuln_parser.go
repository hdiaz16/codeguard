package linters

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

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

func (e DotnetVuln) interpretar(raw []byte, repoRoot, csproj string) ([]finding.Finding, error) {
	var s dnvSalida
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("salida de dotnet list package ilegible en %s: %v", csproj, err)
	}
	// Punto 2 del bloque de arriba: sin esto, un origen NuGet inalcanzable, un
	// assets file ausente o un restore fallido devolverían "0 CVE". Un motor de
	// seguridad que dice "limpio" cuando no pudo mirar es peor que no tenerlo.
	// Cubre las dos formas medidas: salida 0 (origen caído) y salida 1
	// (--no-restore sin assets file), que llega aquí desde revisarProyecto.
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
			Identidad:   finding.IdentidadSemantica,
		}
		if f.Line == 0 {
			f.Line = 1
		}
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
