package manifest

import (
	"crypto/ed25519"
	"encoding/hex"
)

// clavesDeRelease es el registro de claves PÚBLICAS de release embebidas en
// el binario: la raíz de confianza de los rulepacks instalados. El id de
// cada clave se deriva de su propio contenido (keygen lo imprime), así que
// un id no puede apuntar a otra clave sin que la verificación lo delate.
//
// VACÍO tiene semántica deliberada (W3, síntesis t.104): un binario sin
// claves NO puede exigir firma — los rulepacks instalados cargan con
// Verified=false y un aviso, jamás con un rechazo que bloquearía a todo el
// mundo antes del primer release firmado. La exigencia se enciende sola en
// el primer binario que embeba una clave. Un binario de DESARROLLO jamás
// añade claves aquí: embebida una de prueba, cualquier manifest firmado con
// ella sería válido para ese binario — la puerta trasera perfecta.
//
// Para añadir la clave del release: correr `codeguard-release keygen` y
// pegar la línea que imprime.
var clavesDeRelease = map[string]ed25519.PublicKey{}

// clave decodifica una pública embebida escrita en hex. Es dato del binario,
// no entrada externa: si no parsea, el binario está mal construido y reventar
// al arrancar es lo correcto (jamás una raíz de confianza a medias).
//
//lint:ignore U1000 la usan las entradas que keygen imprime para pegar aquí
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
	out := make(map[string]ed25519.PublicKey, len(clavesDeRelease))
	for id, k := range clavesDeRelease {
		out[id] = k
	}
	return out
}
