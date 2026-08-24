package linters

import (
	"crypto/sha256"
	"encoding/hex"
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
			Engine:   "dotnet-build",
			RuleKey:  d.Codigo,
			Pillar:   finding.Quality,
			Severity: sev,
			Blocking: bloquea,
			File:     dnbRelativizar(d.Archivo, bases),
			Line:     d.Linea,
			EndLine:  d.LineaFin,
			Message:  d.Mensaje,
			Why:      dnbPorque(d.Nivel, d.Codigo),
			FixHint:  dnbPista(d.Codigo),
			Verified: true,
			Source:   finding.Deterministic,
			// LineContent lo rellena finding.AsignarHuellas con la línea real
			// (W6, t.128): la v1 hasheaba «regla mensaje» y su alias se
			// reconstruye en contenidoLegacy desde RuleKey+Message. Un
			// diagnóstico de proyecto sin línea legible cae a NoDisponible:
			// visible, bloqueante si es error, pero no baselinable —no se
			// entierra una compilación rota que no se puede ni localizar.
		}
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
// dnbEsManifiestoGlobal reconoce los archivos que afectan a CUALQUIER proyecto
// del repo a cualquier altura: uno en la raíz cambia los analizadores de un
// proyecto que vive tres niveles más abajo.
func dnbEsManifiestoGlobal(base string) bool {
	switch base {
	case "directory.build.props", "directory.build.targets",
		"directory.packages.props", "nuget.config", "global.json", ".editorconfig":
		return true
	}
	return false
}

func claveCsproj(huellas *engines.HuellasRepo, repoRoot, csproj, huellaGlobal string) string {
	ambito := dnbAmbito(repoRoot, csproj)
	prefijos := make([]string, 0, len(ambito))
	for _, p := range ambito {
		if d := path.Dir(p); d == "." {
			prefijos = append(prefijos, "")
		} else {
			prefijos = append(prefijos, d+"/")
		}
	}
	// Los manifiestos globales NO se hashean aquí: pesan en huellaGlobal, que se
	// calcula una sola vez por Run. Antes este predicado los incluía, así que
	// Directory.Build.props y compañía se re-hasheaban una vez por cada .csproj
	// tocado.
	//
	// El recorrido en sí tampoco se repite: `huellas` es un engines.HuellasRepo
	// creado UNA vez en Run, que comparte el `git ls-files` y memoriza los shas.
	// Quitar los manifiestos de aquí ahorró re-hashearlos; compartir el
	// recorrido ahorró volver a enumerar el repo por cada proyecto. Son dos
	// cosas distintas y hicieron falta las dos.
	huella := huellas.Modulo(".", func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		if dnbEsManifiestoGlobal(base) {
			return false
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
	if huellaGlobal == "" || huella == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(huellaGlobal + "|" + huella + "|" + strings.Join(ambito, ",")))
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

// rutaObjPrivado devuelve el directorio intermedio de CodeGuard para un
// proyecto: fuera del repo, en el temporal, y con un nombre derivado de la ruta
// del .csproj Y del proceso. Lo de la ruta evita que dos proyectos se pisen; lo
// del proceso, que dos CodeGuard a la vez sobre el mismo repo (dos commits, o un
// IDE que dispara el hook mientras otro corre) compartan el obj/: MSBuild no
// admite dos builds escribiendo en el mismo directorio intermedio, y un
// artefacto de la otra instancia podía pasar por prueba de ESTA corrida en
// dnbCompiloDeVerdad.
//
// No se borra al terminar a propósito: el mismo proceso lo reutiliza entre
// commits —el daemon vive días con el mismo PID— y con él el restore de NuGet,
// que volver a pagar en cada commit costaría más que el build. Lo que queda
// huérfano al reiniciar vive en el temporal del usuario, que el sistema limpia.
//
// Termina en separador porque MSBuild lo exige en las rutas de salida.
