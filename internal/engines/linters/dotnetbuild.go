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
	"sort"
	"strconv"
	"strings"
	"time"

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
func (e DotnetBuild) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	proys := e.proyectos(in)
	if len(proys) == 0 {
		return nil, nil
	}
	if _, err := exec.LookPath("dotnet"); err != nil {
		return nil, fmt.Errorf("SDK de .NET no disponible: %w", err)
	}
	var out []finding.Finding
	// La huella de los manifiestos globales es la misma para todos los proyectos
	// de este Run: se paga UNA vez y se combina en cada clave, en vez de recorrer
	// el repo entero por cada .csproj para volver a obtener el mismo valor.
	// Vacía = no cacheable, igual que antes: se compila sin caché, no se calla.
	//
	// Y el recorrido del repo se hace una sola vez para TODAS las claves de este
	// Run: antes cada .csproj tocado pagaba su propio `git ls-files` y volvía a
	// hashear los archivos que comparte con los demás (un Core.csproj
	// referenciado por cuatro proyectos se hasheaba cuatro veces).
	huellaGlobal := ""
	var huellas *engines.HuellasRepo
	if e.Cache != nil {
		huellas = engines.LeerHuellasRepo(in.RepoRoot)
		huellaGlobal = huellas.Modulo(".", func(rel string) bool {
			return dnbEsManifiestoGlobal(strings.ToLower(path.Base(rel)))
		})
	}
	for _, proy := range proys {
		clave := ""
		if e.Cache != nil {
			if clave = claveCsproj(huellas, in.RepoRoot, proy, huellaGlobal); clave != "" {
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
			proy := proy
			e.Cache.Guardar([]engines.Cacheable{{
				Clave:    clave,
				Vigente:  engines.VigenciaDeClave(clave, func() string { return claveCsproj(huellas, in.RepoRoot, proy, huellaGlobal) }),
				Findings: fs,
			}})
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
// Y para que Rebuild no sea destructivo, lo que se compila se ESCRIBE en un
// directorio privado fuera del repo: sin esto, el Clean de Rebuild borraría el
// bin/obj del desarrollador (dejándole una recompilación completa de regalo, o
// un fallo seco si el depurador tiene tomado un .dll de bin).
func dnbCompilar(ctx context.Context, repoRoot, csproj string) ([]finding.Finding, error) {
	dirProy := filepath.Join(repoRoot, filepath.FromSlash(path.Dir(csproj)))

	// Se redirige DÓNDE SE ESCRIBE (IntermediateOutputPath / OutputPath) y NO
	// dónde el SDK cree que está obj/ (BaseIntermediateOutputPath). La distinción
	// parece cosmética y no lo es.
	//
	// El SDK excluye del glob de compilación lo que cuelgue de
	// $(BaseIntermediateOutputPath) y $(BaseOutputPath). Al mover los Base*, el
	// obj/ REAL del proyecto dejaba de estar excluido y sus AssemblyInfo.cs de
	// compilaciones anteriores entraban a la nuestra: ocho errores CS0579
	// "Duplicate attribute" sobre archivos que el usuario nunca escribió.
	// Bloqueantes, e inventados. Aparecían en la SEGUNDA corrida —cuando ya hay
	// algo en obj/—, que es justo la corrida normal: la del que reintenta el
	// commit después de que le bloqueen.
	//
	// Excluirlos a mano no funciona: DefaultItemExcludes es una lista separada por
	// ';' y la línea de comandos de MSBuild parte los -p: por ese mismo carácter
	// (MSB1006). Escapado como %3B deja de partirse, pero entonces el ';' es
	// literal y las dos exclusiones se vuelven UN patrón que no casa con nada —
	// medido con `dotnet msbuild -getItem:Compile`: los archivos de obj/ seguían
	// en la lista.
	//
	// Dejando los Base* en su valor por defecto, las exclusiones del SDK siguen
	// siendo las correctas y sólo cambia el destino de la escritura. Medido: los
	// items compilados son exactamente los del usuario, y dos compilaciones
	// seguidas dan el mismo resultado.
	//
	// project.assets.json sigue en el obj/ real, que es donde --no-restore lo
	// busca, porque BaseIntermediateOutputPath no se toca.
	privado := rutaObjPrivado(repoRoot, csproj)

	// La hora de ARRANQUE, que es media prueba de identidad. Ver dnbCompiloDeVerdad.
	inicio := time.Now()

	cmd := exec.CommandContext(ctx, "dotnet", "build", path.Base(csproj),
		"--no-restore", "--nologo", "-v", "quiet", "-clp:NoSummary", "-t:Rebuild",
		"-p:IntermediateOutputPath="+privado,
		"-p:OutputPath="+privado+"bin"+string(os.PathSeparator))
	cmd.Dir = dirProy
	cmd.Env = proc.EntornoDeMotor("dotnet-build", proc.PerfilDotnet) // --no-restore: compila offline
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
	// Y el caso simétrico, que era el que quedaba abierto: SALIÓ BIEN Y CALLÓ.
	//
	// El motor pide silencio a propósito —`-v quiet -clp:NoSummary --nologo`— para
	// que la salida sean sólo diagnósticos. Medido con el SDK 8.0.300 sobre un
	// .csproj que compila: código 0 y CERO bytes. O sea que «compilé tu proyecto y
	// no hay errores» y «no soy dotnet y no he hecho nada» eran la misma respuesta,
	// y la primera es la que el panel pinta en verde.
	//
	// Aquí no hay salida que examinar, pero tampoco hace falta preguntar a nadie
	// quién es: una compilación DEJA UN ARTEFACTO. Se comprueba que exista y que
	// sea de ESTA corrida, porque el directorio privado sobrevive entre commits y
	// un ensamblado viejo dejaría pasar al impostor con la prueba de otro. -t:Rebuild
	// garantiza que se reescriba siempre.
	//
	// Es mejor señal que quitar el -clp:NoSummary para exigir un "Build succeeded":
	// ese texto está traducido en los SDK localizados, y demuestra que algo
	// imprimió, no que algo compilara.
	if codigo == 0 && !dnbHayErrores(diags) {
		if err := dnbCompiloDeVerdad(privado, inicio); err != nil {
			return nil, fmt.Errorf("dotnet build terminó con éxito en %s y no dejó rastro de "+
				"haber compilado: %v. Con `-v quiet` un build correcto no escribe nada, así que "+
				"el silencio no distingue «sin errores» de «no compilé»; el artefacto sí. La capa "+
				"de compilación de C# NO revisó este cambio", csproj, err)
		}
	}

	bases := []string{repoRoot}
	if canon, err := filepath.EvalSymlinks(repoRoot); err == nil && canon != repoRoot {
		bases = append(bases, canon)
	}
	return dnbTraducir(diags, bases), nil
}

// dnbCompiloDeVerdad busca, bajo el directorio privado de salida, algún archivo
// escrito durante esta corrida.
//
// El margen de un segundo hacia atrás es por la resolución de la fecha en el
// sistema de archivos, no por generosidad: sin él, un build de 40 ms podría
// quedar por debajo del instante de arranque y declararse falso.
//
// Se recorre el directorio ENTERO porque un proyecto multi-target reparte sus
// artefactos en un subdirectorio por framework, y basta con uno para demostrar
// que el compilador corrió.
func dnbCompiloDeVerdad(privado string, inicio time.Time) error {
	umbral := inicio.Add(-time.Second)
	var reciente string
	err := filepath.Walk(privado, func(ruta string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || reciente != "" {
			return nil // un directorio ilegible no prueba nada; se sigue buscando
		}
		if !info.ModTime().Before(umbral) {
			reciente = ruta
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("no pude mirar %s: %v", privado, err)
	}
	if reciente == "" {
		return fmt.Errorf("ni un archivo nuevo en %s", privado)
	}
	return nil
}

// dnbParsear extrae los diagnósticos de la salida de MSBuild, deduplicados por
// posición + código + texto (ver el punto 1 y 2 del bloque de arriba).
func rutaObjPrivado(repoRoot, csproj string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Join(repoRoot, filepath.FromSlash(csproj)))))
	dir := filepath.Join(os.TempDir(), "codeguard-obj",
		hex.EncodeToString(sum[:8])+"-"+strconv.Itoa(os.Getpid()))
	return dir + string(os.PathSeparator)
}
