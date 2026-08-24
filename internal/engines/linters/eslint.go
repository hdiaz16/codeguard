package linters

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// ESLint cubre el hueco de formato y estilo en TS/JS. Hasta aquí ese lado del
// producto sólo tenía tsc (tipos) y las reglas de la casa de semgrep: nada de
// formato ni de convenciones, mientras Go llevaba gofmt+govet+staticcheck.
//
// La decisión que da forma a todo el motor: NO IMPONE ESTILO. Corre el linter
// que el repo YA configuró y aplica SUS reglas, no las nuestras. Un proyecto
// que no configura ninguno queda fuera (Applies falso para él), por el mismo
// motivo por el que gofmt no bloquea por finales de línea: hacer fallar un
// commit por una convención que el equipo no eligió convierte al agente en un
// obstáculo, y un obstáculo se desinstala.
//
// Un solo Engine sabe correr las dos herramientas del ecosistema porque son
// alternativas excluyentes del mismo trabajo, no capas distintas. El nombre que
// viaja en el hallazgo es el de la herramienta REAL —"eslint" o "biome"— para
// que el dev sepa quién le habla y `codeguard stats` mida por herramienta.
type ESLint struct {
	// Cache es por ARCHIVO (estos linters analizan archivo a archivo, a
	// diferencia de tsc que compila el proyecto entero). La clave lleva además
	// la huella de la configuración: ver claveDeArchivo.
	Cache engines.Cache
}

func (ESLint) Name() string { return "eslint" }

func (e ESLint) Applies(in engines.Input) bool { return len(e.proyectos(in)) > 0 }

// herramienta es cuál de las dos configuró el repo. Es también el valor que va
// en Finding.Engine.
type herramienta string

const (
	hESLint herramienta = "eslint"
	hBiome  herramienta = "biome"
)

// extensionesJS son los archivos que estos linters entienden.
//
// .mts y .cts entran aunque tsc.go sólo mire .ts/.tsx: un módulo TypeScript con
// extensión explícita es código de producción igual, y dejarlo sin lintar sería
// exactamente el punto ciego silencioso que este motor viene a cerrar.
var extensionesJS = []string{".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}

// configsBiome y configsESLint son los manifiestos que declaran "este proyecto
// tiene linter". No se leen: sólo su presencia decide, y su contenido entra en
// la clave de caché.
var configsBiome = []string{"biome.json", "biome.jsonc"}

// El orden importa dentro de eslint: da igual cuál se encuentre primero, todos
// significan lo mismo. Se incluyen los .eslintrc heredados a propósito — eslint
// 10 ya no los soporta, pero un repo con .eslintrc tiene eslint 8 clavado en su
// package.json, y es SU binario el que corremos. Detectar la intención del repo
// y ejecutar su herramienta son dos cosas distintas.
var configsESLint = []string{
	"eslint.config.js", "eslint.config.mjs", "eslint.config.cjs", "eslint.config.ts",
	"eslint.config.mts", "eslint.config.cts",
	".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.mjs",
	".eslintrc.json", ".eslintrc.yml", ".eslintrc.yaml",
}

// proyectoJS es un grupo de archivos tocados que comparten configuración: el
// directorio del manifiesto, la herramienta que declara y los archivos que le
// tocan.
type proyectoJS struct {
	dir      string // relativo a la raíz, "." si es la propia raíz
	tool     herramienta
	archivos []gitdiff.ChangedFile
}

// proyectos agrupa los archivos JS/TS tocados por el manifiesto de linter más
// cercano, subiendo desde cada archivo (el mismo descubrimiento que tsc.go: en
// el monorepo típico la configuración vive en frontend/, no en la raíz, y mirar
// sólo la raíz deja la compuerta enrolada sin correr jamás).
func (ESLint) proyectos(in engines.Input) []proyectoJS {
	idx := map[string]*proyectoJS{}
	for _, f := range in.Files {
		if f.Status == "D" || !esJS(f.Path) {
			continue
		}
		dir, tool, ok := linterDe(in.RepoRoot, f.Path)
		if !ok {
			continue // proyecto sin linter configurado: no es asunto nuestro
		}
		clave := dir + "\x00" + string(tool)
		p := idx[clave]
		if p == nil {
			p = &proyectoJS{dir: dir, tool: tool}
			idx[clave] = p
		}
		p.archivos = append(p.archivos, f)
	}
	out := make([]proyectoJS, 0, len(idx))
	for _, p := range idx {
		out = append(out, *p)
	}
	// Orden estable: el informe no debe cambiar de forma entre dos corridas
	// idénticas sólo por el recorrido de un mapa.
	sort.Slice(out, func(i, j int) bool {
		if out[i].dir != out[j].dir {
			return out[i].dir < out[j].dir
		}
		return out[i].tool < out[j].tool
	})
	return out
}

func esJS(rel string) bool {
	ext := strings.ToLower(path.Ext(rel))
	for _, e := range extensionesJS {
		if ext == e {
			return true
		}
	}
	return false
}

// linterDe sube desde el archivo hasta el primer directorio que configure un
// linter, sin salirse de la raíz ni entrar a node_modules.
//
// Cuando un mismo directorio configura las dos, gana biome. No es un empate
// arbitrario: biome.json aparece en un repo porque alguien MIGRÓ a biome, y la
// migración deja el eslintrc viejo atrás durante semanas. Elegir eslint ahí
// aplicaría las reglas que el equipo acaba de abandonar. El orden inverso
// —biome primero— es el que respeta la decisión más reciente.
//
// La comprobación es por nivel, no global: si la raíz tiene biome.json y
// frontend/ tiene eslint.config.js, un archivo de frontend/ se linta con
// eslint. Gana lo más cercano, y sólo se desempata dentro del mismo directorio.
func linterDe(repoRoot, rel string) (string, herramienta, bool) {
	if strings.Contains(rel, "node_modules/") {
		return "", "", false
	}
	dir := path.Dir(rel)
	for {
		abs := filepath.Join(repoRoot, filepath.FromSlash(dir))
		if hayAlguno(abs, configsBiome) {
			return dir, hBiome, true
		}
		if hayAlguno(abs, configsESLint) {
			return dir, hESLint, true
		}
		if dir == "." || dir == "/" {
			return "", "", false
		}
		dir = path.Dir(dir)
	}
}

func hayAlguno(absDir string, nombres []string) bool {
	for _, n := range nombres {
		if st, err := os.Stat(filepath.Join(absDir, n)); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

// maxLineaComandosJS acota los argumentos de una invocación.
//
// El límite aquí NO es el de semgrep. Los binarios de node se instalan como
// shims .cmd (node_modules\.bin\eslint.cmd, y npx.cmd), o sea scripts batch:
// Windows los ejecuta a través de cmd.exe, que corta en 8191 caracteres — no en
// los 32767 de CreateProcess. La primera versión de este motor usó 30000
// copiando la razón de semgrep (que invoca un .exe de verdad) y murió en el
// primer repo real con frontend: `codeguard report` sobre portal-cliente degradó el
// motor con el mensaje de cmd.exe, "The command line is too long".
//
// 6000 deja sitio de sobra para la ruta del binario y las banderas. El troceado
// existía ya; lo que estaba mal era el número.
const maxLineaComandosJS = 6000

// objetivoJS es un archivo a analizar: la ruta que recibe la herramienta
// (relativa al proyecto), la que viaja en el hallazgo (relativa al repo) y su
// clave de caché.
type objetivoJS struct {
	rel   string // relativo al repo, separador /
	enPry string // relativo al directorio del proyecto
	clave string // vacío = no cacheable
	sha   string // la huella del contenido que la clave describe (bug #8)
}

func (e ESLint) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, p := range e.proyectos(in) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fs, err := e.correrProyectoJS(ctx, in.RepoRoot, p)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

func (e ESLint) correrProyectoJS(ctx context.Context, repoRoot string, p proyectoJS) ([]finding.Finding, error) {
	// La huella de la configuración se calcula UNA vez por proyecto: es la parte
	// cara de la clave y es idéntica para todos sus archivos.
	huella := ""
	if e.Cache != nil {
		huella = huellaConfigJS(repoRoot, p.dir)
	}

	var pendientes []objetivoJS
	for _, f := range p.archivos {
		o := objetivoJS{rel: f.Path, enPry: enProyecto(p.dir, f.Path)}
		if huella != "" && f.SHA256 != "" {
			o.clave = claveDeArchivo(p.tool, huella, f.SHA256)
			o.sha = f.SHA256
		}
		pendientes = append(pendientes, o)
	}

	// ── Aciertos de caché ──
	var findings []finding.Finding
	if e.Cache != nil {
		var claves []string
		for _, o := range pendientes {
			if o.clave != "" {
				claves = append(claves, o.clave)
			}
		}
		findings, pendientes = reproducirAciertosJS(e.Cache.Leer(claves), pendientes)
	}
	if len(pendientes) == 0 {
		return findings, nil
	}

	rutas := make([]string, len(pendientes))
	for i, o := range pendientes {
		rutas[i] = o.enPry
	}

	var nuevos []finding.Finding
	for _, lote := range lotesDeRutas(rutas, maxLineaComandosJS) {
		fs, err := correrLinterJS(ctx, repoRoot, p.dir, p.tool, lote)
		if err != nil {
			return nil, err
		}
		nuevos = append(nuevos, fs...)
	}
	if e.Cache != nil {
		e.Cache.Guardar(cacheDeArchivosJS(nuevos, pendientes, repoRoot))
	}
	return append(findings, nuevos...), nil
}

// reproducirAciertosJS separa los objetivos servidos por caché de los que
// quedan por analizar, y devuelve los hallazgos cacheados ya atribuidos al
// archivo de ESTA corrida.
//
// El caché está direccionado por CONTENIDO (la clave no lleva la ruta), así
// que dos archivos idénticos comparten entrada; al reproducir un acierto hay
// que reescribir la ruta y recalcular el fingerprint, o el hallazgo saldría
// atribuido al otro archivo. Mismo mecanismo que semgrep.
func reproducirAciertosJS(aciertos map[string][]finding.Finding, pendientes []objetivoJS) (findings []finding.Finding, quedan []objetivoJS) {
	for _, o := range pendientes {
		fs, ok := aciertos[o.clave]
		if o.clave == "" || !ok {
			quedan = append(quedan, o)
			continue
		}
		for _, f := range fs {
			if f.File != o.rel {
				f.File = o.rel
			}
			findings = append(findings, f)
		}
	}
	return findings, quedan
}

// claveDeArchivo compone la clave de caché de un archivo.
//
// El sha del contenido NO basta. Las reglas que se aplican a ese contenido
// vienen de la configuración del repo, y editar .eslintrc cambia los hallazgos
// sin tocar una sola línea de código: servir el resultado viejo sería reportar
// las reglas de ayer. Por eso la clave es herramienta + huella de la config +
// contenido, y no sólo lo último.
//
// La herramienta va delante porque eslint y biome dan hallazgos distintos para
// el mismo archivo, y un repo a mitad de migración tiene proyectos de las dos
// convivendo.
