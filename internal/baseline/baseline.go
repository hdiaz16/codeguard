// Package baseline lee y escribe .codeguard/baseline.txt: los fingerprints
// de hallazgos preexistentes (§17 paso 4). El archivo se versiona en el repo
// para que hook, daemon y CI supriman exactamente lo mismo.
package baseline

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"codeguard/internal/finding"
	"codeguard/internal/fsutil"
)

const RelPath = ".codeguard/baseline.txt"

// Load devuelve los fingerprints suprimidos. Sin archivo → mapa vacío y
// error nil. Un archivo que no se puede leer ENTERO es error, no un mapa
// parcial: devolver lo leído hasta el corte suprimiría sólo una parte de
// la deuda aceptada, y nadie sabría por qué unos hallazgos se suprimen y
// otros vuelven a bloquear.
func Load(repoRoot string) (map[string]bool, error) {
	f, err := os.Open(filepath.Join(repoRoot, filepath.FromSlash(RelPath)))
	if err != nil {
		// Solo "no existe" es el caso de mapa vacío. Permisos denegados, un
		// directorio en la ruta o un error de disco NO son "sin baseline": con
		// el nil,nil de antes, LoadOrWarn no tenía error que registrar y el
		// aviso que existe justo para esto no salía nunca — el equipo veía
		// bloquear de golpe toda la deuda aceptada sin una línea que lo dijera.
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, fmt.Errorf("baseline ilegible (%s): %w", RelPath, err)
	}
	defer f.Close()
	out := map[string]bool{}
	v1Vivas := 0
	sc := bufio.NewScanner(f)
	// El buffer por defecto (64 KB) corta una línea larga con ErrTooLong y
	// Scan() lo disfraza de EOF: la baseline salía truncada sin ruido. Una
	// línea legítima aquí es un fingerprint hex + comentario humano, así
	// que 1 MB es holgura, no una invitación a abusar.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// formato: <fingerprint>  # comentario humano
		if i := strings.IndexByte(line, ' '); i > 0 {
			line = line[:i]
		}
		if v, ok := finding.ParseHuella(line); ok && v == 1 {
			v1Vivas++
		}
		out[line] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("baseline ilegible (%s): %w", RelPath, err)
	}
	// El aviso del cierre de la ventana lleva FECHA y CONTEO (turno 76: sin
	// números, el aviso se aprende a ignorar). Las entradas v1 se cargan igual
	// —quien decide si casan es HuellasDeBusqueda, que ya no emite el alias—
	// así que esto no cambia el veredicto: lo EXPLICA antes de que alguien
	// pregunte por qué su deuda aceptada volvió a bloquear.
	if v1Vivas > 0 && !finding.VentanaDualActiva(time.Now()) {
		log.Printf("baseline: %d entrada(s) v1 YA NO SUPRIMEN (la ventana dual cerró el %s) — corre `codeguard baseline --solo-renovar`",
			v1Vivas, finding.SunsetV1)
	}
	return out, nil
}

// LoadOrWarn es Load para los llamadores que no pueden propagar un error
// (literales de struct, condiciones de una línea). Ante una baseline
// ilegible degrada a "no hay supresiones" —fail-closed: más alertas, nunca
// suprimir de más— y LO DICE en el log en vez de fingir que no pasó nada.
// El nombre admite la degradación; quien pueda devolver error, use Load.
func LoadOrWarn(repoRoot string) map[string]bool {
	m, err := Load(repoRoot)
	if err != nil {
		log.Printf("baseline: %v — se ignora la baseline: nada se suprime en esta corrida", err)
		return nil
	}
	return m
}

// Write serializa la baseline con comentarios legibles para revisión en PR.
// Devuelve además cuántos hallazgos quedaron FUERA por ambiguos, para que el
// llamador lo diga: una baseline que calla lo que no pudo aceptar deja al
// equipo esperando una supresión que no va a ocurrir.
func Write(repoRoot string, findings []finding.Finding) (int, int, error) {
	seen := map[string]bool{}
	ambiguos := 0
	var lines []string
	for _, f := range findings {
		if f.Engine == "gitleaks" || f.Fingerprint == "" || seen[f.Fingerprint] {
			continue // los secretos jamás entran a la baseline
		}
		// Un hallazgo AMBIGUO (otro de la misma corrida produjo la misma
		// huella: mismo texto y mismo contexto) no entra: su entrada no
		// demostraría CUÁL de las ocurrencias se aceptó (turno 83, defecto 2)
		// y suprimiría a las dos. Se cuenta y el llamador lo anuncia; el
		// remedio es distinguir las ocurrencias en el código o aceptar que
		// sigan a la vista.
		if f.HuellaAmbigua {
			ambiguos++
			continue
		}
		// Identidad incompleta (W6, t.128): un hallazgo cuya línea no se pudo
		// leer no tiene una huella estable, así que baselinarlo enterraría lo
		// que venga después con la misma regla/ruta. Se salta y sigue a la
		// vista — la falla va hacia bloquear, jamás hacia suprimir a ciegas.
		if f.NoSuprimible {
			ambiguos++
			continue
		}
		// El formato es un fingerprint por línea, así que un '\n' en cualquier
		// campo inyecta líneas —incluidos fingerprints ajenos— en el archivo
		// que hook, daemon y CI toman como verdad de supresión. En Windows el
		// nombre de archivo no puede traerlo, pero la clave de regla sí: la
		// ponen los motores desde la configuración del repo analizado. Y el
		// fingerprint tiene que ser un token limpio, porque al leer de vuelta
		// Load corta por el primer espacio y salta lo que empiece por '#'.
		// Se rechaza en vez de escapar: Load no podría des-escapar sin cambiar
		// un formato que está versionado. Abortar es la dirección segura —la
		// baseline no se regenera y los hallazgos siguen bloqueando.
		if strings.ContainsAny(f.Fingerprint+f.RuleKey+f.File, "\n\r") ||
			strings.ContainsAny(f.Fingerprint, " #") {
			return 0, 0, fmt.Errorf("baseline: campos no serializables en hallazgo (regla %q, archivo %q)", f.RuleKey, f.File)
		}
		seen[f.Fingerprint] = true
		lines = append(lines, fmt.Sprintf("%s  # %s %s:%d", f.Fingerprint, f.RuleKey, f.File, f.Line))
	}
	sort.Strings(lines)

	path := filepath.Join(repoRoot, filepath.FromSlash(RelPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, 0, err
	}
	// La línea de huellas es INFORMATIVA (quien manda es el binario y su
	// ParseHuella): existe para que un humano que abra el archivo sepa qué
	// formato tiene delante y por qué conviven dos.
	header := "# CodeGuard baseline — hallazgos preexistentes suprimidos (§17 paso 4).\n" +
		"# Solo lo NUEVO bloquea. Regenerar con: codeguard baseline\n" +
		"# Los secretos nunca se suprimen.\n" +
		"# Huellas: v2 (las v1 de binarios anteriores siguen valiendo durante la ventana dual).\n"
	content := header + strings.Join(lines, "\n") + "\n"
	// Atómico: la baseline se versiona y la leen hook, daemon y CI; un
	// archivo truncado por un crash a media escritura haría reaparecer la
	// deuda aceptada (o perderla) sin que nadie supiera por qué.
	if err := fsutil.EscribirAtomico(path, []byte(content), 0o644); err != nil {
		return 0, 0, err
	}
	return len(lines), ambiguos, nil
}

// ResumenRenovacion cuenta lo que Renovar hizo con cada entrada v1, y las
// listas nombran lo que exige atención humana: un resumen sin nombres es de
// los que se aprenden a ignorar.
type ResumenRenovacion struct {
	Migradas      int      // v1 con UN hallazgo vivo que casa: reescrita como v2
	YaMigradas    int      // ya eran v2: se conservan tal cual
	Desaparecidas []string // sin hallazgo vivo que case: la deuda ya no existe (se retiran)
	Conservadas   []string // >1 candidato o candidato ambiguo: decisión humana, se conservan como v1
	Desconocidas  []string // formato que este binario no entiende: se conservan y se dice
}

// Renovar migra las entradas v1 de la baseline al formato v2 SIN re-admitir
// nada (turnos 83-84): una entrada solo se reescribe cuando exactamente UN
// hallazgo vivo la reproduce por su alias legacy — cero candidatos es deuda
// que ya no existe (se retira con aviso), y más de uno (el caso #9: las
// ocurrencias que colapsaban) o un candidato ambiguo exigen decisión humana
// y la entrada v1 SE CONSERVA: sigue supriendo por la ventana dual, que es
// exactamente el tiempo que el humano tiene para decidir. Lo que esta
// función jamás hace: aceptar hallazgos vivos que no casaban con ninguna
// entrada — eso sería regenerar, no renovar.
//
// Trabaja sobre las LÍNEAS del archivo y no sobre el mapa de Load a
// propósito: los comentarios de las entradas conservadas son de humanos y
// sobreviven; solo la línea migrada estrena comentario (el del hallazgo vivo).
func Renovar(repoRoot string, vivos []finding.Finding) (ResumenRenovacion, error) {
	var r ResumenRenovacion
	path := filepath.Join(repoRoot, filepath.FromSlash(RelPath))
	raw, err := os.ReadFile(path)
	if err != nil {
		return r, fmt.Errorf("no hay baseline que renovar: %w", err)
	}

	porLegacy := map[string][]*finding.Finding{}
	for i := range vivos {
		f := &vivos[i]
		if f.Engine == "gitleaks" || f.LegacyFingerprint == "" {
			continue
		}
		porLegacy[f.LegacyFingerprint] = append(porLegacy[f.LegacyFingerprint], f)
	}

	var out []string
	for _, linea := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		l := strings.TrimSpace(linea)
		if l == "" || strings.HasPrefix(l, "#") {
			out = append(out, linea)
			continue
		}
		token := l
		if i := strings.IndexByte(l, ' '); i > 0 {
			token = l[:i]
		}
		version, ok := finding.ParseHuella(token)
		switch {
		case !ok:
			// Jamás se adivina: se conserva (Load la ignorará al no casar con
			// nada) y se nombra.
			r.Desconocidas = append(r.Desconocidas, linea)
			out = append(out, linea)
		case version == 2:
			r.YaMigradas++
			out = append(out, linea)
		default: // v1
			candidatos := porLegacy[token]
			switch {
			case len(candidatos) == 0:
				r.Desaparecidas = append(r.Desaparecidas, linea)
				// no se re-emite: la deuda ya no existe o no se pudo re-casar
			case len(candidatos) == 1 && !candidatos[0].HuellaAmbigua:
				f := candidatos[0]
				out = append(out, fmt.Sprintf("%s  # %s %s:%d", f.Fingerprint, f.RuleKey, f.File, f.Line))
				r.Migradas++
			default:
				// El caso #9 en vivo: varias ocurrencias comparten la v1 (o la
				// v2 salió ambigua). La entrada se CONSERVA como v1 — sigue
				// supriendo mientras dure la ventana — y el humano decide.
				r.Conservadas = append(r.Conservadas, linea)
				out = append(out, linea)
			}
		}
	}
	contenido := strings.Join(out, "\n")
	if !strings.HasSuffix(contenido, "\n") {
		contenido += "\n"
	}
	if err := fsutil.EscribirAtomico(path, []byte(contenido), 0o644); err != nil {
		return r, err
	}
	return r, nil
}
