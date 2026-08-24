// Package registry lleva la lista de proyectos enrolados en esta máquina.
// Se alimenta de `codeguard init` y de cada análisis, para que el panel y el
// explorador muestren TODOS los proyectos — no solo los que ya commitearon.
package registry

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"codeguard/internal/fsutil"
)

type Repo struct {
	Root     string `json:"root"`
	Nombre   string `json:"nombre"`
	Alta     string `json:"alta"`    // cuándo se enroló
	UltVez   string `json:"ult_vez"` // último análisis
	Lenguaje string `json:"lenguaje,omitempty"`
}

var mu sync.Mutex

// path es dónde vive el registro, con un único invariante: SIEMPRE una ruta
// absoluta, o nada.
//
// La guarda era `base == ""`, que atrapa exactamente el caso de la variable
// ausente y ningún otro. filepath.Join no falla con los demás: con "   " sale
// `   \codeguard\repos.json` y con un valor relativo `datos\local\codeguard\...`,
// los dos RELATIVOS al directorio de trabajo — que durante un commit es el
// repositorio del usuario. Y aquí no sólo se lee: este MkdirAll y los WriteFile
// de Add/Load/Remove CREAN el directorio, así que al desarrollador le aparecían
// archivos dentro de su árbol que git le ofrecía añadir al commit siguiente.
// Medido: con LOCALAPPDATA=`datos\local` aparece `datos\`, y con "." aparece
// `codeguard\`.
//
// (Con "   " no llegaba a escribir, pero por accidente: Windows rechaza un
// componente hecho sólo de espacios y fallaba el MkdirAll. Escapar de la guarda
// y que te salve el sistema operativo no es lo mismo que estar protegido.)
//
// Es la misma clase que H007, N001, N003 y la BD de runs, con la misma lección:
// la guarda va donde se RESUELVE la ruta, y hay que comprobar la propiedad que
// se quiere —filepath.IsAbs— en vez de deducirla comparando contra "". Se usa
// la misma semántica que store.DefaultPath y cmd/codeguard.dirDatos para no
// inventar una cuarta forma de decir lo mismo: absoluta, o el temporal, o nada.
//
// Devolver "" es seguro para todos los llamadores: los ReadFile devuelven error
// y Load/Remove ya lo tratan como "no hay registro", y los WriteFile son
// best-effort declarado. Es preferible a inventar una ruta, porque un registro
// escrito en el sitio equivocado no se nota hasta que faltan proyectos.
func path() string {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "codeguard")
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(os.TempDir(), "codeguard")
	}
	if !filepath.IsAbs(dir) {
		return ""
	}
	_ = os.MkdirAll(dir, 0o755) // si falla, la escritura de abajo dará el error real
	return filepath.Join(dir, "repos.json")
}

// Load devuelve los proyectos conocidos, ordenados por nombre.
func Load() []Repo {
	mu.Lock()
	defer mu.Unlock()
	raw, err := os.ReadFile(path())
	if err != nil {
		return nil
	}
	var repos []Repo
	if json.Unmarshal(raw, &repos) != nil {
		return nil
	}
	// El registro se sanea al leerlo, no sólo al escribirlo: el panel lee por
	// aquí, y los archivos que vienen de versiones anteriores traen la misma
	// carpeta repetida en varias escrituras.
	repos, colapsado := colapsar(repos)
	// los que ya no existen en disco se olvidan solos — pero sólo cuando la
	// inexistencia es REAL. Un os.Stat que falla por permisos, una unidad de
	// red caída o un montaje dormido no prueba que el repo desapareció, y
	// olvidarlo aquí lo borraría del archivo PARA SIEMPRE por un error
	// transitorio. Ante la duda, el repo se conserva.
	alive := make([]Repo, 0, len(repos))
	for _, r := range repos {
		if _, err := os.Stat(r.Root); err == nil || !errors.Is(err, fs.ErrNotExist) {
			alive = append(alive, r)
		}
	}
	// Y se olvidan de verdad: antes se filtraban en cada lectura pero el
	// archivo conservaba la entrada muerta para siempre, así que cualquier
	// otro lector la seguía viendo.
	if len(alive) != len(repos) || colapsado {
		if data, err := json.MarshalIndent(alive, "", "  "); err == nil {
			// Atómico: un crash a media escritura ya no trunca el registro.
			_ = fsutil.EscribirAtomico(path(), data, 0o644) // best-effort: Load tolera que falte o falle
		}
	}
	sort.Slice(alive, func(i, j int) bool { return alive[i].Nombre < alive[j].Nombre })
	return alive
}

// Add registra (o actualiza) un proyecto. Idempotente.
func Add(root, nombre, lenguaje string) {
	// La ruta se canoniza AQUÍ, en la frontera de escritura, y no sólo al
	// consultar: si lo que se persiste no es canónico, dos escrituras de la
	// misma carpeta son dos proyectos distintos por más que luego se comparen
	// bien. El invariante es del dato guardado, no de la comparación.
	root = rutaCanonica(root)
	mu.Lock()
	defer mu.Unlock()
	var repos []Repo
	if raw, err := os.ReadFile(path()); err == nil {
		// Si el archivo existe pero no se puede parsear, NO seguimos: escribir
		// encima perdería los demás proyectos por un JSON corrupto pasajero.
		// Pero tampoco se traga en silencio: sin esto, `codeguard init` no daba
		// error y el proyecto nunca aparecía en el panel, sin pista de por qué.
		if err := json.Unmarshal(raw, &repos); err != nil {
			log.Printf("registro corrupto en %s: %v (repararlo o borrarlo a mano)", path(), err)
			return
		}
	}
	// Add no pasa por Load: si no colapsara también aquí, reescribiría los
	// duplicados que Load acabara de limpiar.
	repos, _ = colapsar(repos)
	now := time.Now().Format(time.RFC3339)
	found := false
	for i := range repos {
		// Ambas ya son canónicas; en Windows sólo queda ignorar mayúsculas.
		if strings.EqualFold(repos[i].Root, root) {
			repos[i].Nombre = nombre
			repos[i].UltVez = now
			if lenguaje != "" {
				repos[i].Lenguaje = lenguaje
			}
			found = true
			break
		}
	}
	if !found {
		repos = append(repos, Repo{Root: root, Nombre: nombre, Alta: now, UltVez: now, Lenguaje: lenguaje})
	}
	if data, err := json.MarshalIndent(repos, "", "  "); err == nil {
		// Atómico: un crash a media escritura ya no trunca el registro.
		_ = fsutil.EscribirAtomico(path(), data, 0o644) // best-effort: Load tolera que falte o falle
	}
}

// rutaCanonica devuelve la forma que el disco reconoce como suya: absoluta,
// con los nombres largos y la capitalización REALES (resuelve HECTOR~1 →
// "Hector Diaz"), separadores / y sin barra final. Es la única forma que se
// persiste en Root, y conserva las mayúsculas porque ese campo se le enseña
// al usuario en el panel.
func rutaCanonica(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
		// Falla si el directorio ya no existe; entonces vale la absoluta, que
		// Load descartará por no estar en disco.
		if resuelto, err := filepath.EvalSymlinks(abs); err == nil {
			p = resuelto
		}
	}
	return strings.TrimRight(filepath.ToSlash(p), "/")
}

// normalizarRuta es la IDENTIDAD de un proyecto: su ruta canónica en
// minúsculas, porque en Windows dos rutas que sólo difieren en mayúsculas son
// el mismo directorio. Add, Load y Remove comparan SIEMPRE por aquí; tener dos
// definiciones de "es el mismo repo" fue justo el fallo (H028): Add comparaba
// la cadena cruda y Remove ésta, así que la misma carpeta escrita de dos
// formas —la corta de %TEMP% y la larga— entraba dos veces al registro.
func normalizarRuta(p string) string { return strings.ToLower(rutaCanonica(p)) }

// colapsar impone el invariante del archivo: una entrada por directorio
// físico, con Root canónico. Devuelve además si tuvo que tocar algo, para
// poder reescribir el archivo sólo cuando hace falta.
//
// Actúa también sobre lo YA guardado: los repos.json escritos por las
// versiones que no canonizaban al escribir arrastran duplicados, y sin
// arreglarlos al leer el problema seguiría en pantalla para siempre.
func colapsar(repos []Repo) ([]Repo, bool) {
	out := make([]Repo, 0, len(repos))
	donde := map[string]int{} // identidad → posición en out
	cambio := false
	for _, r := range repos {
		canon := rutaCanonica(r.Root)
		if canon != r.Root {
			cambio = true
			r.Root = canon
		}
		id := strings.ToLower(canon)
		i, repetida := donde[id]
		if !repetida {
			donde[id] = len(out)
			out = append(out, r)
			continue
		}
		out[i] = fundir(out[i], r)
		cambio = true
	}
	return out, cambio
}

// fundir junta dos representaciones del mismo proyecto: manda la del análisis
// más reciente, que es el estado de verdad, pero se conserva el alta más
// antigua — "cuándo se enroló" es la primera vez, no la del duplicado que
// apareció después— y no se pierden los datos que la ganadora no traiga.
func fundir(a, b Repo) Repo {
	gana, otra := a, b
	if instante(b.UltVez).After(instante(a.UltVez)) {
		gana, otra = b, a
	}
	if otra.Alta != "" && (gana.Alta == "" || instante(otra.Alta).Before(instante(gana.Alta))) {
		gana.Alta = otra.Alta
	}
	if gana.Nombre == "" {
		gana.Nombre = otra.Nombre
	}
	if gana.Lenguaje == "" {
		gana.Lenguaje = otra.Lenguaje
	}
	return gana
}

// instante lee una marca del registro. Una ilegible o ausente vale como la más
// antigua posible: comparar estas cadenas como texto se rompería en cuanto dos
// entradas tuvieran husos distintos (un portátil que cruzó de zona horaria).
func instante(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// Remove saca un proyecto del registro. Devuelve si estaba.
//
// Load ya olvida los repos que desaparecieron del disco, así que esto sólo
// hace falta cuando el repo sigue ahí y lo que se quiere es dejar de
// vigilarlo. Vive aquí, en Go, porque el formato es nuestro: manipular este
// archivo desde PowerShell salió mal —ConvertTo-Json desenvuelve los arreglos
// de un elemento y el registro dejaba de ser una lista.
func Remove(root string) bool {
	root = normalizarRuta(root)
	mu.Lock()
	defer mu.Unlock()
	raw, err := os.ReadFile(path())
	if err != nil {
		return false
	}
	var repos []Repo
	if json.Unmarshal(raw, &repos) != nil {
		return false
	}
	quedan := make([]Repo, 0, len(repos))
	quitado := false
	for _, r := range repos {
		if normalizarRuta(r.Root) == root {
			quitado = true
			continue
		}
		quedan = append(quedan, r)
	}
	if !quitado {
		return false
	}
	if data, err := json.MarshalIndent(quedan, "", "  "); err == nil {
		// Atómico: un crash a media escritura ya no trunca el registro.
		_ = fsutil.EscribirAtomico(path(), data, 0o644) // best-effort: Load tolera que falte o falle
	}
	return true
}
