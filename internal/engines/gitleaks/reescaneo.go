package gitleaks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/gitdiff"
)

// nombreArbol es la carpeta, DENTRO del temporal, donde cuelga lo que se
// reescanea. Que el contenido no esté en la raíz no es cosmético: gitleaks lee
// su configuración de `(target)/.gitleaks.toml` y SÓLO de la raíz del target.
// Medido: el mismo .gitleaks.toml que apaga la compuerta desde la raíz (código
// 0, cero hallazgos) no hace nada un nivel más abajo (código 9, el secreto
// encontrado). Apuntando gitleaks al temporal y dejando los archivos en esta
// subcarpeta, la configuración del repo analizado viaja como contenido a
// escanear y no como órdenes que obedecer.
//
// Alcance exacto, medido con una mutación (target = este directorio en vez del
// temporal): el anidado sostiene el ataque del .gitleaks.toml y SÓLO ése. El
// del .gitleaksignore no lo cierra esto, lo cierra que su huella sea
// `archivo:regla:línea` con la ruta ABSOLUTA del temporal dentro: como la raíz
// temporal es aleatoria, la huella no se puede escribir por adelantado. Vale la
// pena saberlo por si algún día se quiere una raíz fija por rendimiento —
// tendría precio.
//
// El nombre es raro a propósito: la ruta que devuelve gitleaks se corta por el
// PRIMER componente que se llame así, y un repo puede tener perfectamente un
// directorio "arbol".
const nombreArbol = "arbol-codeguard"

// topeReescaneo acota lo que se copia al temporal. Ver el mensaje de error de
// abajo para el porqué de que pasarse BLOQUEE en vez de saltarse el resto.
const topeReescaneo = 64 << 20

// origen dice de qué archivo del repo salió una copia y a qué línea real
// corresponde cada línea de la copia.
type origen struct {
	ruta   string
	lineas []int
}

// linea traduce un número de línea de la copia al del archivo de verdad.
func (o origen) linea(n int) int {
	if n >= 1 && n <= len(o.lineas) {
		return o.lineas[n-1]
	}
	return n
}

// reescaneoNeutral vuelve a pasar la tijera por lo que entra en el commit, pero
// desde fuera del alcance del repositorio analizado.
//
// EL PROBLEMA QUE CIERRA: el repo decidía su propia vigilancia. Cinco maneras
// distintas de meter un secreto con `git commit` saliendo 0, las cinco medidas
// contra gitleaks 8.30.1 con un control válido al lado (el mismo token en texto
// plano bloquea: código 9, reporte de 526 B):
//
//	.gitattributes con `creds.txt -diff`     git no emite contenido → 0 bytes escaneados
//	un byte NUL dentro del archivo           git lo declara binario → 0 bytes escaneados
//	.gitleaks.toml con [allowlist] `.*`      escanea 104 bytes y calla los hallazgos
//	.gitleaksignore con la huella            la huella es `archivo:regla:línea`, se adivina
//	un comentario `# gitleaks:allow`         basta pegarlo al lado del secreto
//
// Los cinco archivos VIAJAN CON EL REPO: no apagan la compuerta del que ataca,
// la apagan para todo el que clone. Y los cinco dan código 0, reporte `[]` y
// cero líneas ERR/FTL, así que el discriminante que ya teníamos —«gitleaks
// contó un error propio, su silencio no vale»— no puede verlos, y no es culpa
// suya: git funciona y gitleaks funciona. Aquella cerraba la clase «falló algo»;
// ésta es la clase «no había nada que mirar, o me dijeron que no mirara».
//
// Es la MISMA CLASE que N007, donde un repo apagaba las 119 reglas de la casa
// vendoreando su rulepack. Aquello se arregló para semgrep y no para gitleaks.
//
// CÓMO SE CIERRA, y por qué así y no de la manera que parecía obvia. La idea
// descartada era detectar el sabotaje: «si nuestro diff ve texto y gitleaks
// dice que escaneó ~0 bytes, es que le taparon algo». Se midió y es falsa por
// los dos lados. Por arriba, un PNG de 20 KB produce 14 líneas añadidas que git
// llama binarias: el criterio bloquearía todo commit que añada una imagen. Por
// abajo, con el .gitattributes en el mismo commit gitleaks declara ~16 bytes y
// no ~0, así que ni siquiera dispara. Un NUL plantado y un binario de verdad no
// se distinguen por su forma; sólo se distinguen mirando el contenido.
//
// Así que en vez de detectar el punto ciego se CUBRE: se copian las líneas que
// el commit añade —leídas con --text, que es lo que destapa lo que git escondía—
// a un árbol temporal, y se le pasa gitleaks en modo directorio, que no consulta
// .gitattributes, ni el .gitleaks.toml del repo, ni su .gitleaksignore. Ahí el
// binario legítimo sigue sin dar hallazgos, porque el que descarta binarios es
// gitleaks con su propio criterio de contenido, no una heurística nuestra.
//
// Los hallazgos de las dos pasadas se SUMAN: el repo puede añadir reglas
// propias, que la pasada 1 sigue aplicando, pero ya no puede quitar ninguna.
//
// Cada pieza está medida por mutación, y cada una sostiene exactamente un
// vector — si alguna estorba algún día, esto dice qué se cae con ella:
//
//	--text en el diff        → sin él vuelven a entrar 1 (.gitattributes) y 2 (NUL)
//	target = el temporal     → sin él vuelve a entrar 3 (.gitleaks.toml)
//	--ignore-gitleaks-allow  → sin él vuelve a entrar 5 (# gitleaks:allow)
//
// Y la pasada entera, quitada de golpe, devuelve los cinco. El control —el
// mismo token en texto plano— sigue bloqueando en las cinco mutaciones, que es
// lo que prueba que los rojos son de los ataques y no de un gitleaks averiado.
//
// CONSECUENCIA QUE HAY QUE SABER: `# gitleaks:allow` deja de silenciar en
// CodeGuard, y los secretos no se baselinan. Para un fixture con pinta de
// secreto, la convención de la casa es partir el literal en dos (ver
// `patDePrueba`), que es lo que este mismo repo hace y lo que sigue funcionando.
func (e *Engine) reescaneoNeutral(ctx context.Context, bin string, in engines.Input) ([]leak, error) {
	var anadidas map[string][]gitdiff.LineaAnadida
	var err error
	switch e.Mode {
	case "staged":
		anadidas, err = gitdiff.AnadidasComoTextoStaged(in.RepoRoot)
	case "range":
		anadidas, err = gitdiff.AnadidasComoTextoRango(in.RepoRoot, e.Base, e.Head)
	default:
		return nil, fmt.Errorf("%w: modo desconocido %q", ErrUnavailable, e.Mode)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: no pude releer el diff forzando texto, así que no puedo "+
			"comprobar lo que git no enseña: %v — comprueba el repositorio "+
			"(`git status`, `git fsck`) y vuelve a intentarlo", ErrUnavailable, err)
	}
	if len(anadidas) == 0 {
		// Nada que entre en el commit: sólo borrados, sólo renombrados, o el
		// índice vacío. Los tres son legítimos y frecuentes, y los tres tienen
		// que pasar sin ruido (medidos: ninguno bloquea).
		return nil, nil
	}

	raiz, err := os.MkdirTemp("", "codeguard-reescaneo-*")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = os.RemoveAll(raiz) }()

	arbol := filepath.Join(raiz, nombreArbol)
	tabla := make(map[string]origen, len(anadidas))
	var total int64
	for ruta, lineas := range anadidas {
		rel, n, err := copiar(arbol, ruta, lineas)
		if err != nil {
			return nil, fmt.Errorf("%w: no pude preparar la copia de %s para reescanearla: %v",
				ErrUnavailable, ruta, err)
		}
		total += n
		if total > topeReescaneo {
			// Fail-closed y no «me salto el resto»: saltárselo en silencio es
			// justo la mentira que este arreglo existe para retirar — el commit
			// pasaría con parte del contenido sin mirar y sin que nadie lo
			// dijera. Que bloquee es incómodo, pero el tope son 64 MB de texto
			// AÑADIDO en un solo commit, que no es un commit de trabajo.
			return nil, fmt.Errorf("%w: este commit añade más de %d MB de contenido y no puedo "+
				"reescanearlo entero, así que no puedo afirmar que esté limpio. "+
				"Sepáralo en commits más pequeños, o saca los archivos grandes a Git LFS",
				ErrUnavailable, topeReescaneo>>20)
		}
		tabla[rel] = origen{ruta: ruta, lineas: numeros(lineas)}
	}

	// cmd.Dir es el temporal, NO el repo: si gitleaks buscara algo relativo a su
	// directorio de trabajo, tiene que encontrar el nuestro.
	args := []string{"dir", "--redact", "--report-format", "json", "--report-path", "",
		"--exit-code", "9", "--no-banner", "--ignore-gitleaks-allow", raiz}
	leaks, err := e.correr(ctx, bin, raiz, args)
	if err != nil {
		return nil, err
	}

	// Devolver las rutas del temporal sería peor que no decir nada: mandaría al
	// dev a un directorio que ya no existe.
	for i := range leaks {
		rel := dentroDelArbol(leaks[i].File)
		o, ok := tabla[rel]
		if !ok {
			// No debería pasar. Si pasa, el hallazgo NO se descarta —es un
			// secreto— y se reporta con lo mejor que tenemos.
			leaks[i].File = rel
			continue
		}
		leaks[i].File = o.ruta
		leaks[i].StartLine = o.linea(leaks[i].StartLine)
		leaks[i].EndLine = o.linea(leaks[i].EndLine)
	}
	return leaks, nil
}

func numeros(lineas []gitdiff.LineaAnadida) []int {
	ns := make([]int, len(lineas))
	for i, l := range lineas {
		ns[i] = l.Linea
	}
	return ns
}

// copiar escribe las líneas añadidas de un archivo bajo arbol y devuelve la
// ruta relativa con que quedó, y cuántos bytes ocupó.
//
// Se intenta primero espejar la ruta del repo, porque hay reglas de gitleaks
// que miran el NOMBRE del archivo y con un nombre inventado dejarían de
// aplicar. Si el sistema de archivos no la admite —un nombre reservado de
// Windows, una ruta demasiado larga— se cae a un nombre plano derivado del
// hash: peor nombre, pero el contenido se mira igual. Lo que no se hace nunca
// es saltarse el archivo, que es como se pierden los hallazgos sin que nadie
// se entere.
func copiar(arbol, ruta string, lineas []gitdiff.LineaAnadida) (string, int64, error) {
	var buf bytes.Buffer
	for _, l := range lineas {
		buf.WriteString(l.Texto)
		buf.WriteByte('\n')
	}

	rel := filepath.ToSlash(ruta)
	if seguro(rel) {
		destino := filepath.Join(arbol, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(destino), 0o700); err == nil {
			if err := os.WriteFile(destino, buf.Bytes(), 0o600); err == nil {
				return rel, int64(buf.Len()), nil
			}
		}
	}

	sum := sha256.Sum256([]byte(rel))
	plano := hex.EncodeToString(sum[:8]) + "-" + saneado(filepath.Base(rel))
	if err := os.MkdirAll(arbol, 0o700); err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(filepath.Join(arbol, plano), buf.Bytes(), 0o600); err != nil {
		return "", 0, err
	}
	return plano, int64(buf.Len()), nil
}

// seguro rechaza lo que no puede colgar del árbol sin salirse de él. git no
// produce estas rutas, pero es la frontera con contenido del repositorio
// analizado y aquí no se confía en que el de enfrente se porte bien.
func seguro(rel string) bool {
	if rel == "" || strings.HasPrefix(rel, "/") || filepath.IsAbs(rel) {
		return false
	}
	if len(rel) > 1 && rel[1] == ':' { // C:\... aunque venga con barras normales
		return false
	}
	for _, parte := range strings.Split(rel, "/") {
		if parte == ".." || parte == "" {
			return false
		}
	}
	return true
}

func saneado(nombre string) string {
	limpio := strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`<>:"/\|?*`, r) {
			return '_'
		}
		return r
	}, nombre)
	if limpio == "" {
		return "archivo"
	}
	return limpio
}

// dentroDelArbol saca la ruta relativa al árbol de la ruta ABSOLUTA que reporta
// gitleaks. Se busca el componente por su nombre y no se recorta por longitud
// del prefijo porque en Windows la raíz temporal puede llegar en forma corta
// 8.3 (`HECTOR~1`) y volver en forma larga, o al revés — el mismo alias que hace
// desaparecer hallazgos de mypy cuando la ruta del proyecto lo tiene.
func dentroDelArbol(p string) string {
	barras := strings.ReplaceAll(p, `\`, "/")
	marca := "/" + nombreArbol + "/"
	i := strings.Index(strings.ToLower(barras), strings.ToLower(marca))
	if i < 0 {
		return barras
	}
	return barras[i+len(marca):]
}
