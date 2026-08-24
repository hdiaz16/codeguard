// Package trivy adapta el escáner de dependencias vulnerables (sección 6.2.5).
// Corre solo cuando cambió un manifiesto o lockfile. Política §7: CVE crítico
// advierte en local y bloquea en CI (la DB local puede estar desactualizada).
package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
	"codeguard/internal/trivydb"
)

type Engine struct {
	Binary string
	// BlockCritical: true en CI (la DB está recién actualizada), false en local.
	BlockCritical bool
	// SkipDBUpdate: true en el camino del hook; el daemon/CI refrescan la DB.
	SkipDBUpdate bool
	// Cache: mismos manifiestos = mismos CVE, sin re-escanear. La clave lleva
	// el día UTC — la política local ya acepta una DB del día (SkipDBUpdate),
	// pero un acierto de la semana pasada escondería CVEs nuevos.
	Cache engines.Cache
}

func (e *Engine) Name() string { return "trivy" }

// manifests reconoce manifiestos y lockfiles de los ecosistemas soportados.
var manifests = map[string]bool{
	"package.json": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"go.mod": true, "go.sum": true,
	"requirements.txt": true, "poetry.lock": true, "pipfile.lock": true, "uv.lock": true,
	"pom.xml": true, "build.gradle": true, "build.gradle.kts": true, "gradle.lockfile": true,
	"packages.lock.json": true, "pubspec.lock": true,
}

func (e *Engine) changedManifests(in engines.Input) []string {
	var out []string
	for _, f := range in.Files {
		if f.Status == "D" {
			continue
		}
		base := strings.ToLower(path.Base(f.Path))
		if manifests[base] || strings.HasSuffix(base, ".csproj") {
			out = append(out, f.Path)
		}
	}
	return out
}

func (e *Engine) Applies(in engines.Input) bool { return len(e.changedManifests(in)) > 0 }

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// clave identifica un escaneo: la huella de TODOS los manifiestos rastreados
// del repo (el escaneo es fs sobre la raíz, no por archivo) más el día UTC.
func (e *Engine) clave(repoRoot string) string {
	huella := engines.HuellaModulo(repoRoot, ".", func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		return manifests[base] || strings.HasSuffix(base, ".csproj")
	})
	if huella == "" {
		return ""
	}
	return "trivy:" + huella + ":" + time.Now().UTC().Format("2006-01-02")
}

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "trivy"
	}
	clave := ""
	if e.Cache != nil {
		if clave = e.clave(in.RepoRoot); clave != "" {
			if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
				// El caché guarda HECHOS (qué CVEs hay), no política: Blocking
				// se recalcula aquí con el BlockCritical de ESTE proceso. Si se
				// sirviera tal cual, un acierto guardado en local permisivo
				// dejaría pasar CVEs críticos en CI (misma clave, mismo día).
				// La huella no incluye Blocking, así que la identidad del
				// hallazgo frente a baselines no cambia al recalcular.
				// Se copia para no mutar la memoria que devuelve el caché.
				out := make([]finding.Finding, len(fs))
				copy(out, fs)
				for i := range out {
					out[i].Blocking = out[i].Severity == finding.Error && e.BlockCritical
				}
				return out, nil
			}
		}
	}
	// --skip-db-update va SIEMPRE, y no es un matiz: dejar que trivy se
	// actualice solo hace pasar datos del registro remoto por oras-go, que
	// arrastra un CVE sin corrección publicada (la excepción #6). Cuando toca
	// refrescar (el CI, donde SkipDBUpdate llega en falso), la base la baja
	// CodeGuard con su propio cliente OCI (internal/trivydb), que verifica cada
	// digest antes de abrir nada.
	if !e.SkipDBUpdate {
		dir, errDir := dirCacheTrivy()
		if errDir != nil {
			// Sin ruta de caché no se puede ni bajar ni comprobar la base, y
			// seguir con una relativa rompería el invariante de que CodeGuard y
			// trivy miran EXACTAMENTE el mismo sitio.
			return nil, errDir
		}
		if err := trivydb.Actualizar(ctx, dir); err != nil {
			// Sin base no hay escaneo posible: trivy fallaría con un mensaje
			// ajeno ("--skip-db-update cannot be specified on the first run").
			// Con base vieja se sigue: detectar con la base de ayer gana por
			// mucho a no detectar, y el fallo queda dicho en vez de callado.
			if _, statErr := os.Stat(filepath.Join(dir, "db", "metadata.json")); statErr != nil {
				return nil, fmt.Errorf("no hay base de vulnerabilidades y no se pudo bajar: %w", err)
			}
			// «Queda dicho» lo prometía el comentario y el código lo callaba: el
			// error se evaporaba en esta rama, así que una base semanas sin
			// refrescar por un fallo de red persistente no se notaba.
			log.Printf("trivy: no se pudo actualizar la base de vulnerabilidades, "+
				"se escanea con la copia local (puede estar desactualizada): %v", err)
		}
	}
	args := []string{"fs", "--scanners", "vuln", "--format", "json", "--quiet", "--skip-db-update"}
	args = append(args, in.RepoRoot)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = in.RepoRoot
	cmd.Env = proc.EntornoDePerfil(proc.PerfilBasico) // corre SIEMPRE con --skip-db-update; la DB la baja trivydb (Go propio), no el motor
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	out := salida.Stdout
	// Sin --exit-code, trivy sale con 0 aunque encuentre vulnerabilidades: un
	// código distinto de cero es fallo de ejecución, nunca "hay hallazgos".
	// Tolerar el error cuando hubo stdout convertía un reporte parcial en
	// veredicto bueno — y abajo se cacheaba con clave diaria, así que el
	// "limpio" a medias se servía el resto del día. La única excepción es
	// ErrWaitDelay: el escaneo ya salió con 0 y la salida está completa, solo
	// quedó un nieto reteniendo los pipes más allá del plazo (ver proc.Correr).
	if runErr != nil && !errors.Is(runErr, exec.ErrWaitDelay) {
		return nil, fmt.Errorf("trivy falló: %w", runErr)
	}
	if salida.Recortada {
		return nil, fmt.Errorf("trivy devolvió más de %d MB de salida", proc.MaxSalida>>20)
	}
	var report trivyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("salida de trivy ilegible: %v", err)
	}

	var findings []finding.Finding
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			critical := v.Severity == "CRITICAL"
			sev := finding.Warning
			if critical {
				sev = finding.Error
			}
			fix := "Sin versión corregida publicada todavía; evalúa mitigar o sustituir la dependencia."
			if v.FixedVersion != "" {
				fix = fmt.Sprintf("Actualiza %s de %s a %s.", v.PkgName, v.InstalledVersion, v.FixedVersion)
			}
			f := finding.Finding{
				Engine:      "trivy",
				RuleKey:     v.VulnerabilityID,
				Pillar:      finding.Security,
				Severity:    sev,
				Blocking:    critical && e.BlockCritical,
				File:        filepath.ToSlash(r.Target),
				Line:        1,
				Message:     fmt.Sprintf("%s en %s@%s: %s", v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.Title),
				Why:         "OWASP A03 2025 (cadena de suministro): una dependencia con CVE conocido es superficie de ataque directa.",
				FixHint:     fix,
				Verified:    true,
				Source:      finding.Deterministic,
				LineContent: v.PkgName + "@" + v.InstalledVersion,
				Identidad:   finding.IdentidadSemantica,
			}
			findings = append(findings, f)
		}
	}
	if e.Cache != nil && clave != "" {
		// Se persisten hechos puros (Blocking en falso): la política depende
		// de e.BlockCritical, que la clave no incluye y cambia entre local y
		// CI. Quien lee recalcula (ver arriba); guardar la decisión tomada
		// aquí sería congelar política dentro de datos cacheados. Se copia
		// para no tocar los findings que se devuelven a este llamante.
		hechos := make([]finding.Finding, len(findings))
		copy(hechos, findings)
		for i := range hechos {
			hechos[i].Blocking = false
		}
		e.Cache.Guardar([]engines.Cacheable{{
			Clave:    clave,
			Vigente:  engines.VigenciaDeClave(clave, func() string { return e.clave(in.RepoRoot) }),
			Findings: hechos,
		}})
	}
	return findings, nil
}

// dirCacheTrivy vive ahora en el paquete dueño de la base (trivydb.DirCache):
// la auditoría de identidad necesita el MISMO cálculo y dos copias eran la
// receta para bajar la base a un sitio y leerla de otro.
func dirCacheTrivy() (string, error) { return trivydb.DirCache() }
