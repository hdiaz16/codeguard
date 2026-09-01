package manifest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ReleaseKeys es el registro de claves PÚBLICAS que build-dist inyecta con
// -ldflags -X. Formato: id=hex[,id=hex]. Es la raíz de confianza de los
// rulepacks instalados y queda dentro de cada binario estable, no en un archivo
// reemplazable junto al rulepack.
//
// VACÍO tiene semántica deliberada (W3, síntesis t.104): un binario sin
// claves NO puede exigir firma — los rulepacks instalados cargan con
// Verified=false y un aviso, jamás con un rechazo que bloquearía a todo el
// mundo antes del primer release firmado. build-dist, en cambio, falla si no
// puede obtener una clave real y siempre inyecta una. Así un binario de
// desarrollo jamás confía accidentalmente en una clave de prueba.
var ReleaseKeys string

// clave decodifica una pública embebida escrita en hex. Es dato del binario,
// no entrada externa: si no parsea, el binario está mal construido y reventar
// al arrancar es lo correcto (jamás una raíz de confianza a medias).
//
func clave(hexStr string) ed25519.PublicKey {
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("manifest: clave de release embebida malformada: " + hexStr)
	}
	return ed25519.PublicKey(b)
}

// ClavesDeRelease devuelve una copia del registro (nadie muta la raíz de
// confianza en caliente).
func ClavesDeRelease() map[string]ed25519.PublicKey {
	out, err := ParsearClavesDeRelease(ReleaseKeys)
	if err != nil {
		panic(err)
	}
	return out
}

// ParsearClavesDeRelease hace estricto el valor inyectado: una entrada
// ambigua, duplicada o cuyo id no corresponda a la pública aborta el arranque.
// Una raíz de confianza parcialmente interpretada sería peor que no arrancar.
func ParsearClavesDeRelease(valor string) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	if strings.TrimSpace(valor) == "" {
		return out, nil
	}
	for _, entrada := range strings.Split(valor, ",") {
		partes := strings.Split(entrada, "=")
		if len(partes) != 2 || partes[0] == "" || partes[1] == "" || strings.TrimSpace(entrada) != entrada {
			return nil, fmt.Errorf("manifest: registro de claves de release malformado")
		}
		id, hexPublica := partes[0], partes[1]
		if _, existe := out[id]; existe {
			return nil, fmt.Errorf("manifest: clave de release duplicada: %s", id)
		}
		publica, err := hex.DecodeString(hexPublica)
		if err != nil || len(publica) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("manifest: clave pública de release inválida: %s", id)
		}
		suma := sha256.Sum256(publica)
		if esperado := "rel-" + hex.EncodeToString(suma[:4]); id != esperado {
			return nil, fmt.Errorf("manifest: id %s no corresponde a su clave pública", id)
		}
		out[id] = ed25519.PublicKey(publica)
	}
	return out, nil
}
