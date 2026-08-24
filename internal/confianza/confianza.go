// Package confianza cierra el hueco de la clase «config ejecutable» (W4, Q3,
// decisión de Héctor 2026-08-23: la mejor opción, no la más rápida). Un repo
// hostil trae configuración que es CÓDIGO —eslint.config.js, un target de
// MSBuild, un plugin de mypy— o un binario en node_modules/.bin que el repo
// controla, y los motores lo ejecutan con los permisos del dev. El test
// determinista de proc lo probó: el token restringido no limita el
// filesystem, así que ese código toca fuera del árbol.
//
// El cierre es DEFAULT-SEGURO con opt-in TOFU FUERA del repo (síntesis del
// consejo t.116, fusión Kimi+GPT): mientras el usuario no CONFÍE
// explícitamente en la config ejecutable de un repo, los motores que la
// ejecutan se DEGRADAN (no corren). El registro de confianza vive en
// %LOCALAPPDATA%, atado a repo+digest — jamás en el repo, para que la misma
// PR que trae la config hostil no pueda traer también su propia
// autorización (condición de GPT). Es TOFU: el humano teclea `codeguard
// confiar` una vez por repo, y si la config ejecutable cambia (nuevo digest),
// vuelve a preguntarse (condición de Kimi).
package confianza

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/fsutil"
	"codeguard/internal/gitdiff"
)

// motoresQueEjecutanConfig son los que corren código o binarios que el repo
// analizado controla. Lo NO listado no requiere confianza: lee datos (semgrep
// solo el rulepack local, trivy paquetes, gofmt/govet/etc. el fuente).
var motoresQueEjecutanConfig = map[string]bool{
	"eslint":        true, // eslint.config.js ejecutable + binario node_modules/.bin del repo
	"tsc":           true, // npx --no-install resuelve el typescript del repo
	"mypy":          true, // mypy.ini admite plugins = módulos Python arbitrarios
	"dotnet-build":  true, // targets de MSBuild corren al compilar (-t:Rebuild)
	"dotnet-format": true, // MSBuild evalúa el proyecto, que puede traer targets
}

// Requiere dice si un motor necesita confianza del repo para correr.
func Requiere(motor string) bool { return motoresQueEjecutanConfig[motor] }

// Artefacto es una pieza de config-ejecutable detectada en el repo, con el
// hash de su contenido: editar la config cambia el hash y re-pide confianza.
type Artefacto struct {
	Ruta   string // relativa al repo, en forma slash
	SHA256 string
	Clase  string // "eslint-config" | "mypy-plugins" | "msbuild-target" | "binario-repo"
}

// nombresEslintEjecutable: los eslintrc que son CÓDIGO. Los .json/.yaml/.yml
// son datos y NO requieren confianza — no ejecutan nada.
var nombresEslintEjecutable = map[string]bool{
	"eslint.config.js": true, "eslint.config.mjs": true, "eslint.config.cjs": true,
	"eslint.config.ts": true, "eslint.config.mts": true, "eslint.config.cts": true,
	".eslintrc.js": true, ".eslintrc.cjs": true, ".eslintrc.mjs": true,
}

// Detectar lista los artefactos de config-ejecutable del REPO (no de un
// commit): la confianza es del repositorio entero, porque un eslint.config.js
// en la raíz lo carga el motor aunque el commit actual no lo toque. Recorre
// los directorios de los archivos RASTREADOS y sus ancestros —donde los
// motores buscan config— así el gate del pipeline y `codeguard confiar` ven
// EXACTAMENTE el mismo conjunto (si divergieran, el digest confiado nunca
// casaría con el evaluado). Un repo sin config-ejecutable (Go puro) devuelve
// nada: nada que confiar, ningún motor degradado.
func Detectar(repoRoot string) []Artefacto {
	dirs := directoriosDelRepo(repoRoot)
	vistos := map[string]bool{}
	var arts []Artefacto

	add := func(rel, clase string) {
		rel = filepath.ToSlash(rel)
		if vistos[rel] {
			return
		}
		abs := filepath.Join(repoRoot, filepath.FromSlash(rel))
		h, err := hashArchivo(abs)
		if err != nil {
			return
		}
		vistos[rel] = true
		arts = append(arts, Artefacto{Ruta: rel, SHA256: h, Clase: clase})
	}

	for dir := range dirs {
		absDir := filepath.Join(repoRoot, filepath.FromSlash(dir))
		entradas, err := os.ReadDir(absDir)
		if err != nil {
			continue
		}
		for _, e := range entradas {
			if e.IsDir() {
				// El binario que el repo controla es código arbitrario, no
				// config: su sola presencia (usada por eslint/tsc) es el
				// artefacto más hostil (Kimi t.110). Se marca por el directorio.
				if e.Name() == "node_modules" {
					binDir := filepath.Join(dir, "node_modules", ".bin")
					if _, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(binDir))); err == nil {
						rel := filepath.ToSlash(binDir)
						if !vistos[rel] {
							vistos[rel] = true
							// El digest del binario-repo es el de la lista de sus
							// nombres: si el repo añade o cambia un shim, cambia.
							arts = append(arts, Artefacto{Ruta: rel, SHA256: hashDirLista(filepath.Join(repoRoot, filepath.FromSlash(binDir))), Clase: "binario-repo"})
						}
					}
				}
				continue
			}
			nombre := e.Name()
			rel := filepath.Join(dir, nombre)
			switch {
			case nombresEslintEjecutable[strings.ToLower(nombre)]:
				add(rel, "eslint-config")
			case esMypyConPlugins(nombre, filepath.Join(repoRoot, filepath.FromSlash(rel))):
				add(rel, "mypy-plugins")
			case strings.HasSuffix(strings.ToLower(nombre), ".csproj") &&
				csprojEjecutaTargets(filepath.Join(repoRoot, filepath.FromSlash(rel))):
				add(rel, "msbuild-target")
			}
		}
	}
	sort.Slice(arts, func(i, j int) bool { return arts[i].Ruta < arts[j].Ruta })
	return arts
}

// Digest resume los artefactos en una identidad estable: confiar en un repo
// es confiar en ESTE conjunto exacto de config-ejecutable. Cambia si se
// añade, quita o edita cualquiera.
func Digest(arts []Artefacto) string {
	h := sha256.New()
	h.Write([]byte("codeguard-confianza-v1"))
	h.Write([]byte{0})
	for _, a := range arts {
		h.Write([]byte(a.Ruta))
		h.Write([]byte{0})
		h.Write([]byte(a.SHA256))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// directoriosDelRepo lista los directorios donde buscar config-ejecutable: los
// de los archivos RASTREADOS por git (la vía real). Si el repo no es git
// —tests, o un árbol suelto— cae a un recorrido acotado del filesystem
// (saltando .git y sin descender en node_modules, cuyo .bin se detecta por su
// presencia, no por su contenido). La raíz siempre entra.
func directoriosDelRepo(repoRoot string) map[string]bool {
	dirs := map[string]bool{".": true}
	rutas, err := gitdiff.Rastreados(repoRoot)
	if err == nil && len(rutas) > 0 {
		for _, r := range rutas {
			marcarAncestros(dirs, r)
		}
		return dirs
	}
	// Fallback sin git: recorrer el árbol.
	_ = filepath.WalkDir(repoRoot, func(ruta string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				// node_modules no se desciende, pero su directorio padre ya
				// está en dirs y el .bin se detecta desde ahí.
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return filepath.SkipDir
			}
			return nil
		}
		rel, e := filepath.Rel(repoRoot, filepath.Dir(ruta))
		if e == nil {
			marcarAncestros(dirs, filepath.ToSlash(filepath.Join(rel, d.Name())))
		}
		return nil
	})
	return dirs
}

func marcarAncestros(dirs map[string]bool, rutaArchivo string) {
	d := filepath.Dir(filepath.FromSlash(rutaArchivo))
	for {
		rel := filepath.ToSlash(d)
		if rel == "." || rel == "/" || rel == "" {
			return
		}
		if dirs[rel] {
			return
		}
		dirs[rel] = true
		d = filepath.Dir(d)
	}
}

func esMypyConPlugins(nombre, abs string) bool {
	l := strings.ToLower(nombre)
	if l != "mypy.ini" && l != "setup.cfg" && l != "pyproject.toml" {
		return false
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return false
	}
	// `plugins =` (mypy.ini/setup.cfg) o `plugins = [` (pyproject) — la
	// presencia de la clave basta: activa carga de módulos Python del repo.
	return contieneClave(string(raw), "plugins")
}

func contieneClave(texto, clave string) bool {
	for _, linea := range strings.Split(texto, "\n") {
		t := strings.TrimSpace(linea)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(t), clave) {
			resto := strings.TrimSpace(t[len(clave):])
			if strings.HasPrefix(resto, "=") || strings.HasPrefix(resto, ":") {
				return true
			}
		}
	}
	return false
}

func csprojEjecutaTargets(abs string) bool {
	raw, err := os.ReadFile(abs)
	if err != nil {
		return false
	}
	s := strings.ToLower(string(raw))
	// <Target> con <Exec> o <UsingTask> corre código al compilar. Un csproj
	// solo con <PropertyGroup>/<ItemGroup> es declarativo y no ejecuta nada.
	return strings.Contains(s, "<target") && (strings.Contains(s, "<exec") || strings.Contains(s, "<usingtask"))
}

func hashArchivo(abs string) (string, error) {
	raw, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// hashDirLista resume un directorio por los NOMBRES de sus entradas (no su
// contenido: un node_modules es enorme y su riesgo es que exista un shim que
// el repo controla, no qué bytes tiene hoy). Best-effort.
func hashDirLista(abs string) string {
	entradas, err := os.ReadDir(abs)
	if err != nil {
		return "vacio"
	}
	var nombres []string
	for _, e := range entradas {
		nombres = append(nombres, e.Name())
	}
	sort.Strings(nombres)
	sum := sha256.Sum256([]byte(strings.Join(nombres, "\n")))
	return hex.EncodeToString(sum[:])
}

// ── Registro TOFU en %LOCALAPPDATA% (jamás en el repo) ───────────────────────

type entradaConfianza struct {
	Digest     string `json:"digest"`
	ConfiadoEn string `json:"confiado_en"`
}

func rutaRegistro() (string, bool) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", false
	}
	return filepath.Join(base, "CodeGuard", "confianza.json"), true
}

// claveRepo canonicaliza la ruta del repo para que la clave sea la MISMA la
// escriba quien la escriba: `codeguard confiar` (cwd del usuario) y el hook
// (git rev-parse). EvalSymlinks resuelve el 8.3 y los symlinks de %TEMP% en
// Windows — sin él, confiar desde una ruta y verificar desde su forma
// canónica daban dos claves distintas y la confianza «no pegaba».
func claveRepo(repoRoot string) string {
	abs, err := filepath.Abs(repoRoot)
	if err != nil {
		abs = repoRoot
	}
	if canon, err := filepath.EvalSymlinks(abs); err == nil {
		abs = canon
	}
	return strings.ToLower(filepath.ToSlash(abs))
}

func leerRegistro() map[string]entradaConfianza {
	m := map[string]entradaConfianza{}
	ruta, ok := rutaRegistro()
	if !ok {
		return m
	}
	raw, err := os.ReadFile(ruta)
	if err != nil {
		return m
	}
	_ = json.Unmarshal(raw, &m)
	return m
}

// Confiado dice si el digest actual del repo está en el registro. Fail-closed:
// sin LOCALAPPDATA o con registro ilegible, NADA está confiado (el default
// seguro no depende de poder leer el registro).
func Confiado(repoRoot, digest string) bool {
	if digest == "" {
		return true // no hay config-ejecutable: nada que confiar
	}
	e, ok := leerRegistro()[claveRepo(repoRoot)]
	return ok && e.Digest == digest
}

// Registrar guarda el digest actual como confiado para este repo (TOFU). El
// `ahora` se inyecta para no depender de reloj en tests.
func Registrar(repoRoot, digest, ahora string) error {
	ruta, ok := rutaRegistro()
	if !ok {
		return os.ErrNotExist
	}
	m := leerRegistro()
	m[claveRepo(repoRoot)] = entradaConfianza{Digest: digest, ConfiadoEn: ahora}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
		return err
	}
	return fsutil.EscribirAtomico(ruta, raw, 0o644)
}

// Revocar retira la confianza de un repo: sus motores config-ejecutable
// vuelven a degradarse. No-op si no estaba confiado.
func Revocar(repoRoot string) error {
	ruta, ok := rutaRegistro()
	if !ok {
		return nil
	}
	m := leerRegistro()
	if _, había := m[claveRepo(repoRoot)]; !había {
		return nil
	}
	delete(m, claveRepo(repoRoot))
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.EscribirAtomico(ruta, raw, 0o644)
}

// MotoresDegradados devuelve los nombres de los motores (de la lista dada) que
// deben degradarse porque el repo tiene config-ejecutable no confiada. Vacío
// si no hay config-ejecutable o si el repo ya está confiado.
func MotoresDegradados(repoRoot string, motores []string) ([]Artefacto, []string) {
	arts := Detectar(repoRoot)
	if len(arts) == 0 {
		return nil, nil
	}
	if Confiado(repoRoot, Digest(arts)) {
		return arts, nil
	}
	var degradados []string
	for _, m := range motores {
		if Requiere(m) {
			degradados = append(degradados, m)
		}
	}
	return arts, degradados
}
