package linters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

// DotnetBuild es la compuerta de compilación de C# (§7: BLOQUEA), el equivalente
// de tsc para .NET. Hasta ahora C# sólo tenía formato (dotnet format) y semgrep:
// un `; expected` llegaba entero al CI, que es justo lo que este proyecto
// promete que no pase.
//
// Reporta lo que el compilador y los analizadores Roslyn del PROPIO proyecto ya
// clasificaron: error bloquea, warning avisa. Deliberadamente sin
// -warnaserror — en un código existente convertir cada aviso en bloqueante
// vuelve el hook inusable el primer día y la gente lo desinstala.
//
// El proyecto se busca SUBIENDO desde cada .cs tocado hasta el .csproj más
// cercano, como tsc con el tsconfig.json: en el monorepo corporativo típico
// (backend/Api.csproj + frontend/) nada de esto está en la raíz.
type DotnetBuild struct {
	// Cache: mismo proyecto (fuentes + manifiestos + los proyectos que
	// referencia) = los mismos diagnósticos. Se compila el proyecto ENTERO por
	// un archivo cambiado, así que sin caché cada informe paga la compilación.
	Cache engines.Cache
}

func (DotnetBuild) Name() string { return "dotnet-build" }

func (e DotnetBuild) Applies(in engines.Input) bool { return len(e.proyectos(in)) > 0 }

// proyectos agrupa los .cs cambiados por el .csproj más cercano y devuelve las
// rutas de esos .csproj relativas a la raíz (separador /), ordenadas.
//
// Sobre el .sln: NUNCA se compila la solución. Un .sln en la raíz arrastra
// todos sus proyectos, y compilar veinte por tocar un archivo no cabe en los
// 30 s que comparten todos los motores del hook. El .csproj tocado da el mismo
// veredicto sobre el código que cambió con una fracción del trabajo, y los
// errores que el cambio provoque en OTRO proyecto los caza el CI, que sí
// compila la solución completa.
func (DotnetBuild) proyectos(in engines.Input) []string {
	set := map[string]bool{}
	for _, f := range filesWithExt(in, ".cs") {
		if dnbGenerado(f.Path) {
			continue
		}
		for _, p := range dnbCsprojDe(in.RepoRoot, f.Path) {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// dnbGenerado descarta lo que vive en obj/ o bin/: los .cs que el propio SDK
// genera ahí (AssemblyInfo, los de los generadores de código) no son código del
// equipo, y tratarlos como archivo tocado haría compilar proyectos por un
// artefacto de build.
func dnbGenerado(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		switch strings.ToLower(seg) {
		case "obj", "bin":
			return true
		}
	}
	return false
}

// dnbCsprojDe sube desde el archivo hasta el primer directorio con .csproj, sin
// salirse de la raíz del repo. Devuelve TODOS los .csproj de ese directorio:
// tener dos en la misma carpeta es raro, pero elegir uno "el primero" dejaría
// al otro sin compuerta y en silencio.
func dnbCsprojDe(repoRoot, rel string) []string {
	dir := path.Dir(rel)
	for {
		entradas, err := os.ReadDir(filepath.Join(repoRoot, filepath.FromSlash(dir)))
		if err == nil {
			var enc []string
			for _, ent := range entradas {
				if ent.IsDir() || !strings.EqualFold(path.Ext(ent.Name()), ".csproj") {
					continue
				}
				if dir == "." {
					enc = append(enc, ent.Name())
				} else {
					enc = append(enc, dir+"/"+ent.Name())
				}
			}
			if len(enc) > 0 {
				sort.Strings(enc)
				return enc
			}
		}
		if dir == "." || dir == "/" {
			return nil
		}
		dir = path.Dir(dir)
	}
}

// ── la salida de MSBuild ─────────────────────────────────────────────────────
// Verificado con el SDK 10.0.204. Cada diagnóstico llega en una línea:
//
//	C:\ruta\Roto.cs(7,21): error CS1002: ; expected [C:\ruta\ErrProj.csproj]
//	C:\ruta\VulnProj.csproj : warning NU1510: PackageReference ... (sin línea)
//
// Tres cosas que se descubrieron midiendo, no leyendo la documentación:
//
//  1. `-clp:NoSummary` NO surte efecto en `dotnet build` (sí en `dotnet
//     msbuild`): tras "Build FAILED./succeeded." el resumen REPITE literalmente
//     cada diagnóstico. Se manda igual —por si un SDK futuro lo respeta— pero
//     lo que de verdad evita hallazgos duplicados es la deduplicación de abajo.
//  2. En un proyecto multi-target el mismo aviso llega una vez por TFM, con el
//     sufijo "proj.csproj::TargetFramework=net9.0". La deduplicación también
//     colapsa eso: una posición del código es un hallazgo, no dos.
//  3. Los paths llegan ABSOLUTOS y canonizados por MSBuild aunque el directorio
//     de trabajo venga con alias 8.3 (HECTOR~1), al revés que staticcheck, que
//     los escupe tal cual los recibió. Por eso se prueban las dos formas de la
//     raíz del repo.
var dnbDiagnostico = regexp.MustCompile(
	`^(.+?)(?:\((\d+)(?:,\d+(?:,(\d+),\d+)?)?\))?\s?: (error|warning) ([A-Za-z][A-Za-z0-9_.]*[0-9]): (.*)$`)

type dnbDiag struct {
	Archivo  string
	Linea    int
	LineaFin int
	Nivel    string // "error" | "warning", tal como lo clasificó el compilador
	Codigo   string
	Mensaje  string
}

func (e DotnetBuild) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	proys := e.proyectos(in)
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
			if clave = claveCsproj(in.RepoRoot, proy); clave != "" {
				if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
					out = append(out, fs...)
					continue
				}
			}
		}
		// Un proyecto que no se pudo compilar degrada el motor COMPLETO en vez
		// de aportar sus hallazgos y callar el resto: el pipeline descarta los
		// hallazgos de un motor con error (§14), y presentar la mitad de la
		// cobertura de C# como si fuera toda es exactamente la mentira que
		// este proyecto persigue.
		fs, err := dnbCompilar(ctx, in.RepoRoot, proy)
		if err != nil {
			return nil, err
		}
		if e.Cache != nil && clave != "" {
			e.Cache.Guardar(map[string][]finding.Finding{clave: fs})
		}
		out = append(out, fs...)
	}
	return out, nil
}

// dnbCompilar compila un .csproj y traduce sus diagnósticos.
//
// --no-restore es deliberado: `dotnet build` restaura implícitamente, y eso va
// a la RED. El camino del commit no puede depender de que haya red ni pagar ese
// tiempo. El precio es que hay que distinguir "el proyecto está limpio" de "no
// pude ni empezar porque falta el restore", y esa distinción es el corazón del
// motor: ver dnbFatal.
//
// -t:Rebuild fuerza que el compilador y los analizadores CORRAN. Medido: un
// build incremental que MSBuild considera "al día" imprime CERO avisos, así que
// si el desarrollador ya compiló en su IDE, un build normal aquí devolvería
// "limpio" sin haber mirado nada. Con el caché por huella el rebuild se paga
// una vez por estado del proyecto, no una vez por informe.
//
// Y para que Rebuild no sea destructivo, la compilación vive en su propio
// obj/codeguard: sin esto, el Clean de Rebuild borraría el bin/obj del
// desarrollador (dejándole una recompilación completa de regalo, o un fallo
// seco si el depurador tiene tomado un .dll de bin). MSBuildProjectExtensionsPath
// sigue apuntando al obj/ real porque ahí vive project.assets.json, que es lo
// único que --no-restore necesita encontrar.
func dnbCompilar(ctx context.Context, repoRoot, csproj string) ([]finding.Finding, error) {
	dirProy := filepath.Join(repoRoot, filepath.FromSlash(path.Dir(csproj)))
	cmd := exec.CommandContext(ctx, "dotnet", "build", path.Base(csproj),
		"--no-restore", "--nologo", "-v", "quiet", "-clp:NoSummary", "-t:Rebuild",
		"-p:BaseIntermediateOutputPath=obj/codeguard/",
		"-p:MSBuildProjectExtensionsPath=obj/",
		"-p:BaseOutputPath=obj/codeguard/bin/")
	cmd.Dir = dirProy
	cmd.Env = proc.Entorno()
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	if salida.Recortada {
		return nil, fmt.Errorf("dotnet build devolvió más de %d MB de salida en %s", proc.MaxSalida>>20, csproj)
	}
	codigo := 0
	if runErr != nil {
		var exit *exec.ExitError
		if !errors.As(runErr, &exit) {
			// No arrancó, o venció el plazo: no hay nada que interpretar.
			return nil, fmt.Errorf("dotnet build no corrió en %s: %w", csproj, runErr)
		}
		// Salir con 1 es "hay errores de compilación": la respuesta está en la
		// salida, igual que con staticcheck o semgrep.
		codigo = exit.ExitCode()
	}

	texto := string(salida.Combinada())
	diags := dnbParsear(texto)
	if fatal := dnbFatal(diags); fatal != nil {
		return nil, fmt.Errorf("dotnet build no pudo analizar %s: %s %s %s",
			csproj, fatal.Codigo, fatal.Mensaje, dnbRemedio(fatal.Codigo))
	}
	// El build falló y no hay ni un error legible: algo impidió el análisis
	// (MSBuild no cargó el proyecto, el SDK no resolvió, un diagnóstico sin
	// código). Cero hallazgos aquí sería la peor respuesta posible, así que se
	// degrada con lo que dijo la herramienta.
	if codigo != 0 && !dnbHayErrores(diags) {
		return nil, fmt.Errorf("dotnet build falló en %s (código %d) sin errores legibles: %s",
			csproj, codigo, dnbRecorte(texto))
	}

	bases := []string{repoRoot}
	if canon, err := filepath.EvalSymlinks(repoRoot); err == nil && canon != repoRoot {
		bases = append(bases, canon)
	}
	return dnbTraducir(diags, bases), nil
}

// dnbParsear extrae los diagnósticos de la salida de MSBuild, deduplicados por
// posición + código + texto (ver el punto 1 y 2 del bloque de arriba).
func dnbParsear(texto string) []dnbDiag {
	vistos := map[string]bool{}
	var out []dnbDiag
	for _, cruda := range strings.Split(texto, "\n") {
		m := dnbDiagnostico.FindStringSubmatch(strings.TrimRight(strings.TrimSpace(cruda), "\r"))
		if m == nil {
			continue
		}
		mensaje, _ := dnbSinProyecto(m[6])
		d := dnbDiag{
			Archivo: filepath.ToSlash(m[1]),
			Nivel:   m[4],
			Codigo:  m[5],
			Mensaje: mensaje,
		}
		// Sin línea (diagnóstico del proyecto entero, como los NU): la 1 del
		// manifiesto, que es donde el desarrollador va a mirar.
		d.Linea = 1
		if m[2] != "" {
			d.Linea, _ = strconv.Atoi(m[2])
		}
		if m[3] != "" {
			if fin, _ := strconv.Atoi(m[3]); fin > d.Linea {
				d.LineaFin = fin
			}
		}
		clave := strings.ToLower(d.Archivo) + "|" + strconv.Itoa(d.Linea) + "|" +
			strconv.Itoa(d.LineaFin) + "|" + d.Nivel + "|" + d.Codigo + "|" + d.Mensaje
		if vistos[clave] {
			continue
		}
		vistos[clave] = true
		out = append(out, d)
	}
	return out
}

// dnbSinProyecto quita el sufijo " [C:\ruta\proj.csproj]" que MSBuild pega al
// final de cada diagnóstico (en multi-target, con "::TargetFramework=net9.0"
// detrás). Se comprueba que el interior parezca un manifiesto antes de cortar:
// un mensaje que acabe legítimamente en corchetes no debe perder texto.
func dnbSinProyecto(mensaje string) (string, string) {
	i := strings.LastIndex(mensaje, " [")
	if i < 0 || !strings.HasSuffix(mensaje, "]") {
		return mensaje, ""
	}
	interior := mensaje[i+2 : len(mensaje)-1]
	bajo := strings.ToLower(interior)
	esProyecto := strings.Contains(bajo, ".csproj") || strings.Contains(bajo, ".vbproj") ||
		strings.Contains(bajo, ".fsproj") || strings.Contains(bajo, ".proj") ||
		strings.Contains(bajo, ".sln")
	if !esProyecto {
		return mensaje, ""
	}
	return strings.TrimSpace(mensaje[:i]), interior
}

// dnbCodigosFatales son los códigos con los que MSBuild dice "no llegué a
// compilar", no "tu código está mal". Casi todos son la consecuencia esperada
// de --no-restore; los MSB* son el proyecto o el SDK sin cargar.
//
// Confundir esto con un proyecto limpio es el peor fallo que puede tener un
// motor de CodeGuard: es la misma lección que dejó el escaneo de semgrep que
// anunciaba "0 bloqueantes · COMPLETADO" con 28 hallazgos reales sin mirar
// (ver tipoFatal en internal/engines/semgrep/semgrep.go). Aquí se degrada la
// capa y se dice en voz alta qué hay que hacer.
var dnbCodigosFatales = map[string]bool{
	"NETSDK1004": true, // Assets file '...project.assets.json' not found (medido)
	"NETSDK1005": true, // el assets file no tiene target para este TFM
	"NETSDK1047": true, // el assets file no tiene target para este RID
	"NETSDK1064": true, // paquete resuelto pero ausente de la caché local
	"NU1101":     true, // unable to find package
	"NU1102":     true, // no hay versión que satisfaga el rango
	"NU1103":     true,
	"NU1105":     true, // no se pudo leer el archivo de proyecto
	"NU1201":     true, // proyecto no compatible con el TFM
	"NU1202":     true,
	"NU1301":     true, // origen de paquetes inalcanzable
	"MSB3644":    true, // reference assemblies del framework ausentes
	"MSB4019":    true, // import inexistente
	"MSB4236":    true, // SDK no encontrado
}

func dnbFatal(diags []dnbDiag) *dnbDiag {
	for i := range diags {
		if diags[i].Nivel != "error" {
			continue
		}
		// El nombre del archivo no se traduce en ningún idioma de MSBuild, así
		// que sirve de red por debajo de la lista de códigos: un SDK futuro
		// puede estrenar un código nuevo para el mismo hueco.
		if dnbCodigosFatales[diags[i].Codigo] ||
			strings.Contains(diags[i].Mensaje, "project.assets.json") {
			return &diags[i]
		}
	}
	return nil
}

func dnbRemedio(codigo string) string {
	if strings.HasPrefix(codigo, "NETSDK") || strings.HasPrefix(codigo, "NU") {
		return "Corre `dotnet restore` y vuelve a intentarlo. " +
			"El hook usa --no-restore a propósito (el restore va a la red y el camino del commit no puede depender de ella): " +
			"sin él CodeGuard no puede afirmar que este proyecto esté limpio."
	}
	return "Revisa que el SDK de .NET y los imports del proyecto estén disponibles: sin cargar el proyecto no hay análisis que dar."
}

func dnbHayErrores(diags []dnbDiag) bool {
	for _, d := range diags {
		if d.Nivel == "error" {
			return true
		}
	}
	return false
}

func dnbTraducir(diags []dnbDiag, bases []string) []finding.Finding {
	var out []finding.Finding
	for _, d := range diags {
		// NU1901-NU1904 son los avisos de vulnerabilidad de NuGet por nivel de
		// severidad. Los reporta DotnetVuln, que sabe la severidad real, el
		// GHSA y el pilar de seguridad; repetirlos aquí como aviso de calidad
		// sería el mismo hallazgo con dos nombres, igual que govulncheck no
		// repite la presencia que ya dice trivy.
		switch d.Codigo {
		case "NU1901", "NU1902", "NU1903", "NU1904":
			continue
		}
		sev, bloquea := finding.Warning, false
		if d.Nivel == "error" {
			// §7: la compilación es compuerta bloqueante, como tsc y govet.
			sev, bloquea = finding.Error, true
		}
		f := finding.Finding{
			Engine:      "dotnet-build",
			RuleKey:     d.Codigo,
			Pillar:      finding.Quality,
			Severity:    sev,
			Blocking:    bloquea,
			File:        dnbRelativizar(d.Archivo, bases),
			Line:        d.Linea,
			EndLine:     d.LineaFin,
			Message:     d.Mensaje,
			Why:         dnbPorque(d.Nivel, d.Codigo),
			FixHint:     dnbPista(d.Codigo),
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: d.Codigo + " " + d.Mensaje,
		}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out
}

func dnbPorque(nivel, codigo string) string {
	quien := "el compilador de C#"
	if !strings.HasPrefix(codigo, "CS") {
		quien = "un analizador Roslyn que el propio proyecto tiene activado"
	}
	if nivel == "error" {
		return "Lo rechaza " + quien + ", no una regla de CodeGuard: el CI lo va a rechazar exactamente igual."
	}
	return "Aviso de " + quien + " (" + codigo + "). No bloquea: en código existente subir cada aviso a bloqueante " +
		"con -warnaserror inundaría el commit, y un hook inusable acaba desinstalado."
}

func dnbPista(codigo string) string {
	minus := strings.ToLower(codigo)
	switch {
	case strings.HasPrefix(codigo, "CA"):
		return "Ficha de la regla: https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/" + minus
	case strings.HasPrefix(codigo, "IDE"):
		return "Ficha de la regla: https://learn.microsoft.com/dotnet/fundamentals/code-analysis/style-rules/" + minus
	case strings.HasPrefix(codigo, "CS"):
		return "Corrige lo que señala el mensaje del compilador; la ficha del diagnóstico está en https://learn.microsoft.com/dotnet/csharp/misc/" + minus
	case strings.HasPrefix(codigo, "NU"):
		return "Es un diagnóstico de NuGet sobre las dependencias del proyecto: revisa el PackageReference que menciona el mensaje."
	}
	return "Corrige lo que señala el mensaje; el código " + codigo + " identifica la regla del analizador que lo emitió."
}

// dnbRelativizar recorta la raíz del repo del path absoluto que reporta
// MSBuild, probando sus dos formas (la cruda y la canónica: en Windows el
// directorio de trabajo puede venir con alias 8.3 y MSBuild lo canoniza) y
// comparando sin distinguir mayúsculas, que es como comparan los paths de
// Windows. Un path que no cuelga de la raíz —los targets del SDK, por
// ejemplo— se deja tal cual: mejor uno raro que uno inventado.
func dnbRelativizar(archivo string, bases []string) string {
	f := filepath.ToSlash(archivo)
	for _, b := range bases {
		base := strings.TrimSuffix(filepath.ToSlash(b), "/")
		if base != "" && len(f) > len(base)+1 && f[len(base)] == '/' &&
			strings.EqualFold(f[:len(base)], base) {
			return f[len(base)+1:]
		}
	}
	return f
}

// claveCsproj identifica una compilación: el contenido de todo lo que el
// compilador va a leer.
//
// El ámbito no es sólo el directorio del proyecto: `dotnet build` compila
// también los proyectos referenciados, así que un cambio en Core.csproj puede
// romper el Api.csproj que lo usa. Sin recorrer los ProjectReference, un
// acierto de caché de Api escondería el error que Core acaba de introducir.
// Los manifiestos heredados (Directory.Build.props, .editorconfig...) cuentan a
// cualquier altura: uno en la raíz cambia los analizadores de un proyecto que
// vive tres niveles más abajo. Vacía = no cacheable.
func claveCsproj(repoRoot, csproj string) string {
	ambito := dnbAmbito(repoRoot, csproj)
	prefijos := make([]string, 0, len(ambito))
	for _, p := range ambito {
		if d := path.Dir(p); d == "." {
			prefijos = append(prefijos, "")
		} else {
			prefijos = append(prefijos, d+"/")
		}
	}
	huella := engines.HuellaModulo(repoRoot, ".", func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		switch base {
		case "directory.build.props", "directory.build.targets",
			"directory.packages.props", "nuget.config", "global.json", ".editorconfig":
			return true
		}
		dentro := false
		for _, p := range prefijos {
			if p == "" || strings.HasPrefix(rel, p) {
				dentro = true
				break
			}
		}
		if !dentro {
			return false
		}
		return base == "packages.lock.json" ||
			strings.HasSuffix(base, ".cs") || strings.HasSuffix(base, ".csproj") ||
			strings.HasSuffix(base, ".props") || strings.HasSuffix(base, ".targets") ||
			strings.HasSuffix(base, ".resx")
	})
	if huella == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(huella + "|" + strings.Join(ambito, ",")))
	return "dotnet-build:" + hex.EncodeToString(sum[:])
}

var dnbRefProyecto = regexp.MustCompile(`(?i)<ProjectReference[^>]*\sInclude\s*=\s*"([^"]+)"`)

// dnbAmbito devuelve el .csproj dado y, transitivamente, los que referencia
// (rutas relativas a la raíz, ordenadas). Un ProjectReference que apunta fuera
// del repo se ignora: no se puede seguir su contenido con la huella y meterlo a
// medias haría la clave inestable.
func dnbAmbito(repoRoot, csproj string) []string {
	vistos := map[string]bool{csproj: true}
	cola := []string{csproj}
	for len(cola) > 0 {
		actual := cola[0]
		cola = cola[1:]
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(actual)))
		if err != nil {
			continue
		}
		for _, m := range dnbRefProyecto.FindAllStringSubmatch(string(raw), -1) {
			ref := path.Clean(path.Join(path.Dir(actual), filepath.ToSlash(m[1])))
			if ref == "." || strings.HasPrefix(ref, "../") || path.IsAbs(ref) || vistos[ref] {
				continue
			}
			vistos[ref] = true
			cola = append(cola, ref)
		}
	}
	out := make([]string, 0, len(vistos))
	for p := range vistos {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func dnbRecorte(texto string) string {
	s := strings.Join(strings.Fields(texto), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
