package linters

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

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
// LEE el grafo de dependencias ya resuelto por un `dotnet restore` anterior y
// consulta el índice de avisos de nuget.org: eso incluye las TRANSITIVAS, que son
// la mayoría de los CVEs que se heredan sin saberlo.
//
// El SDK de .NET es del desarrollador, no una herramienta que instalemos: si
// falta, el orquestador etiqueta la capa como "falta:" y no como degradada.
type DotnetVuln struct {
	// BlockCritical: true en CI (política §7, igual que trivy y govulncheck).
	// En local avisa: el índice de avisos puede haber cambiado hace minutos y
	// bloquear un commit por eso, sin que el código haya tocado la dependencia,
	// enseña a la gente a saltarse el hook.
	BlockCritical bool
	// SoloManifiestos: true en el camino del hook. El comando ya NO restaura
	// (--no-restore, ver revisarProyecto), pero SIGUE consultando por la red el
	// índice de avisos de nuget.org (medido: con un origen inalcanzable se queda
	// colgado minutos), así que en local sólo corre cuando cambian las
	// dependencias — el único momento en que la respuesta puede cambiar por algo
	// que hizo el desarrollador. El CI lo corre con cualquier .cs tocado.
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
			// una consulta a la red. Barrer el repo entero por un cambio de
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
//
//  2. Un proyecto LIMPIO se serializa exactamente igual que un proyecto que no
//     se pudo analizar: {"path": "..."} sin "frameworks". Lo único que los
//     distingue es el array "problems". Es la trampa de tipoFatal de semgrep
//     otra vez: cero hallazgos y "no pude mirar" se serializan igual y hay que
//     separarlos a mano.
//
//     Y el código de salida NO sirve para separarlos, en ninguna de las dos
//     direcciones: con un origen NuGet caído el comando sale con 0 llevando un
//     "problems" de nivel error, y con --no-restore sin assets file sale con 1
//     llevando otro (medido, SDK 10.0.204, stderr vacío en ese segundo caso).
//     Por eso el filtro de "problems" es la única puerta, y revisarProyecto
//     pasa por interpretar incluso cuando el proceso salió mal.
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

// dnvNoRestoreCache memoriza por directorio si el SDK que ahí resuelve
// (global.json puede cambiarlo por directorio) anuncia `--no-restore` en su
// ayuda. Los nombres de bandera no se localizan, así que buscar el literal es
// estable en cualquier idioma del SDK.
var dnvNoRestoreCache sync.Map // dir → bool

func dnvSoportaNoRestore(ctx context.Context, dirProy string) bool {
	if v, ok := dnvNoRestoreCache.Load(dirProy); ok {
		return v.(bool)
	}
	// --help no toca red ni escribe obj/: es la sonda más barata que responde
	// exactamente la pregunta que importa (¿este SDK conoce la bandera?).
	cmd := exec.CommandContext(ctx, "dotnet", "list", "package", "--help")
	cmd.Dir = dirProy
	cmd.Env = proc.Entorno()
	salida, err := proc.Correr(ctx, cmd, proc.MaxSalida)
	soporta := err == nil && bytes.Contains(salida.Stdout, []byte("--no-restore"))
	dnvNoRestoreCache.Store(dirProy, soporta)
	return soporta
}

// claveProyecto identifica una consulta: los manifiestos que determinan el
// grafo de dependencias (no los .cs: cambiar código no cambia qué paquetes
// resuelve NuGet) más el día UTC.
func (e DotnetVuln) revisarProyecto(ctx context.Context, repoRoot, csproj string) ([]finding.Finding, error) {
	dirProy := filepath.Join(repoRoot, filepath.FromSlash(path.Dir(csproj)))
	// --no-restore por la MISMA razón que en dotnetbuild (dotnetbuild.go:207), que
	// este motor estaba contradiciendo en el mismo camino del commit: sin él,
	// `dotnet list package` restaura implícitamente. MEDIDO con SDK 10.0.204 sobre
	// un clon sin obj/: el comando CREA project.assets.json y su propia salida
	// declara la fuente usada (api.nuget.org). Eso hacía dos cosas malas —
	// escribir el obj/ REAL del desarrollador, que dotnetbuild evita a conciencia
	// con un obj/ privado por PID; y competir con dotnet-build, que corre en
	// paralelo y lee ese mismo assets file: se OBSERVÓ a dotnet-build degradarse
	// con NETSDK1004 en el mismo segundo en que el restore de este motor creaba el
	// archivo, así que su veredicto dependía de quién ganara la carrera.
	//
	// El precio, dicho claro: en un clon sin `dotnet restore` no hay grafo y este
	// motor NO PUEDE mirar. Ese caso degrada con remedio (abajo), nunca devuelve
	// "0 CVE". Y esto no vuelve el motor independiente de la red: el índice de
	// avisos se sigue consultando por red; lo que se quita es el restore.
	// `--no-restore` NO existe en todos los SDK: el 8.0.3 lo rechaza imprimiendo
	// su AYUDA en stdout ("Description: List all package references…"), que el
	// parser recibía como JSON ilegible ("invalid character 'D'"). Y en ese SDK
	// omitirla es seguro: `list package` no restaura implícitamente — sin assets
	// sale con 1 y un problems JSON pidiendo `dotnet restore` (medido aquí con
	// 8.0.300-preview; la rama de abajo ya convierte ese JSON en remedio). La
	// bandera se manda solo donde el SDK la anuncia, así la protección del obj/
	// se conserva en los SDK que sí restaurarían solos.
	args := []string{"list", path.Base(csproj), "package",
		"--vulnerable", "--include-transitive", "--format", "json"}
	if dnvSoportaNoRestore(ctx, dirProy) {
		args = append(args, "--no-restore")
	}
	cmd := exec.CommandContext(ctx, "dotnet", args...)
	cmd.Dir = dirProy
	cmd.Env = proc.Entorno()
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	if salida.Recortada {
		return nil, fmt.Errorf("dotnet list package devolvió más de %d MB en %s", proc.MaxSalida>>20, csproj)
	}
	if runErr != nil {
		// Con --no-restore, un clon sin restore previo sale con código 1 y el
		// diagnóstico viaja en el JSON de STDOUT, no en stderr. MEDIDO con SDK
		// 10.0.204: stderr VACÍO (0 bytes) y stdout con problems[0].level="error"
		// y el texto "No assets file was found … Please run restore before
		// running this command".
		//
		// Por eso se intenta interpretar antes de dar el "no corrió" genérico: el
		// filtro de problems ya emite el remedio exacto («Corre `dotnet
		// restore`…»), y perderlo dejaría al desarrollador con un fallo opaco
		// teniendo la solución en la mano. Por esta rama no pueden salir
		// hallazgos, sólo el error, así que una corrida fallida no puede acabar
		// en "limpio".
		if _, errJSON := e.interpretar(salida.Stdout, repoRoot, csproj); errJSON != nil {
			return nil, errJSON
		}
		return nil, fmt.Errorf("dotnet list package no corrió en %s: %w%s", csproj, runErr, dnvDetalle(salida.Stderr))
	}
	return e.interpretar(salida.Stdout, repoRoot, csproj)
}
