package identidad

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Excepciones: riesgos conocidos que alguien aceptó por escrito.
//
// La razón de que esto exista, y de que sea tan estricto, es que la auditoría
// se encontró con 26 hallazgos en gitleaks que NO se pueden arreglar
// actualizando: están en dependencias que su autor no ha subido, y gitleaks es
// justamente el motor fail-closed que no podemos dejar de repartir.
//
// Ante eso hay una salida fácil y equivocada — subir el umbral a "sólo
// críticas", o quitar el motor del escaneo — que pone la luz en verde y de paso
// apaga los hallazgos que nadie ha mirado todavía. Lo que hace este archivo es
// lo contrario: obliga a nombrar el riesgo, explicar por qué es asumible aquí,
// firmarlo y ponerle fecha de caducidad. La compuerta sigue roja para todo lo
// demás, y las excepciones se imprimen enteras en cada ejecución.

//go:embed excepciones.json
var excepcionesRaw []byte

// Excepcion es un riesgo aceptado. Sin firma no vale, y sin fecha tampoco.
type Excepcion struct {
	Artefacto string `json:"artefacto"`
	// CVE cubre un hallazgo concreto; Paquete cubre todos los de una
	// dependencia. Uno de los dos, no los dos.
	CVE     string `json:"cve"`
	Paquete string `json:"paquete"`
	// Version acota a una versión concreta de esa dependencia. Vacía = cualquiera,
	// que es más ancho y por eso conviene rellenarla: si el motor sube de versión
	// y arrastra otra distinta, la excepción deja de taparla sola.
	Version     string `json:"version"`
	Motivo      string `json:"motivo"`
	Evidencia   string `json:"evidencia"`
	AceptadaPor string `json:"aceptada_por"`
	Hasta       string `json:"hasta"` // AAAA-MM-DD
}

type librosExcepciones struct {
	Excepciones []Excepcion `json:"excepciones"`
}

var excepcionesCargadas librosExcepciones

func init() {
	if err := json.Unmarshal(excepcionesRaw, &excepcionesCargadas); err != nil {
		panic("registro de excepciones ilegible: " + err.Error()) // archivo nuestro, embebido
	}
}

// vigente responde si esta excepción puede aplicarse hoy, y si no, por qué no.
// El motivo se devuelve para poder decirlo en pantalla: una excepción caducada
// o sin firmar tiene que verse, porque significa que hay un riesgo que alguien
// creyó cubierto y no lo está.
func (e Excepcion) vigente(ahora time.Time) (bool, string) {
	if strings.TrimSpace(e.AceptadaPor) == "" {
		return false, "sin firmar (aceptada_por vacío)"
	}
	if strings.TrimSpace(e.Hasta) == "" {
		return false, "sin fecha de caducidad"
	}
	hasta, err := time.Parse("2006-01-02", e.Hasta)
	if err != nil {
		return false, "fecha ilegible: " + e.Hasta
	}
	// Vale el día entero de la fecha escrita: quien pone 30-11 espera cubrir
	// hasta el final de ese día, no hasta su medianoche inicial.
	if ahora.After(hasta.AddDate(0, 0, 1)) {
		return false, "caducó el " + e.Hasta
	}
	return true, ""
}

func (e Excepcion) cubre(r Riesgo) bool {
	eArt := strings.ToLower(strings.TrimSpace(e.Artefacto))
	rArt := strings.ToLower(strings.TrimSpace(r.Artefacto))
	if eArt == "" {
		return false
	}
	// El artefacto llega como "gitleaks" o como "pmd 7.26.0" según si la ruta
	// instalada lleva versión; se compara con coincidencia exacta o delimitada insensible a mayúsculas.
	if eArt != rArt &&
		!strings.HasPrefix(rArt, eArt+" ") &&
		!strings.HasPrefix(rArt, eArt+"/") &&
		!strings.HasPrefix(rArt, eArt+"\\") &&
		!strings.HasPrefix(rArt, eArt+":") {
		return false
	}
	if e.Version != "" && !strings.EqualFold(e.Version, r.Version) {
		return false
	}
	switch {
	case e.CVE != "":
		return strings.EqualFold(e.CVE, r.CVE)
	case e.Paquete != "":
		return strings.EqualFold(e.Paquete, r.Paquete)
	}
	// Una excepción sin CVE ni paquete taparía el motor entero. Nunca.
	return false
}

// Aceptado empareja un riesgo con la excepción que lo cubre, para poder
// imprimirlo. No se descarta el riesgo: se mueve de columna, y se enseña.
type Aceptado struct {
	Riesgo    Riesgo
	Excepcion Excepcion
}

// aplicarExcepciones separa lo que bloquea de lo que está aceptado, y de paso
// avisa de las excepciones que no sirven — caducadas, sin firma, o que ya no
// cubren nada porque el motor se actualizó y el hallazgo desapareció.
//
// Ese último aviso importa más de lo que parece: una excepción que sobrevive a
// su hallazgo es una puerta abierta esperando a que vuelva a pasar algo por
// ella, y nadie la cierra si nadie la ve.
func aplicarExcepciones(riesgos []Riesgo, ahora time.Time) (bloquean []Riesgo, aceptados []Aceptado, avisos []string) {
	usadas := make([]bool, len(excepcionesCargadas.Excepciones))
	for _, r := range riesgos {
		var cubierto bool
		for i, e := range excepcionesCargadas.Excepciones {
			if !e.cubre(r) {
				continue
			}
			usadas[i] = true
			if ok, _ := e.vigente(ahora); ok {
				aceptados = append(aceptados, Aceptado{Riesgo: r, Excepcion: e})
				cubierto = true
				break
			}
		}
		if !cubierto {
			bloquean = append(bloquean, r)
		}
	}
	for i, e := range excepcionesCargadas.Excepciones {
		if ok, porque := e.vigente(ahora); !ok {
			avisos = append(avisos, fmt.Sprintf("%s / %s: %s — el riesgo sigue bloqueando",
				e.Artefacto, e.Objetivo(), porque))
			continue
		}
		if !usadas[i] {
			avisos = append(avisos, fmt.Sprintf("%s / %s: ya no cubre ningún hallazgo; bórrala",
				e.Artefacto, e.Objetivo()))
		}
	}
	return bloquean, aceptados, avisos
}

// Objetivo describe qué cubre esta excepción, para poder nombrarla en pantalla.
func (e Excepcion) Objetivo() string {
	if e.CVE != "" {
		return e.CVE
	}
	if e.Version != "" {
		return e.Paquete + "@" + e.Version
	}
	return e.Paquete
}
