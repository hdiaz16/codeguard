package manifest

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
)

// Firmar serializa el manifiesto UNA sola vez y firma esos bytes exactos.
// Vive en el mismo paquete que el verificador a propósito (condición de Kimi,
// turno 98): la forma canónica de "qué bytes se firman" no puede divergir
// entre quien firma (build-dist) y quien verifica (el binario en cada carga).
//
// Los dos valores devueltos se escriben VERBATIM a disco (manifest.json y
// manifest.sig). No hay re-serialización legítima: un manifiesto reformateado
// tiene una firma inválida y eso es lo correcto.
//
// Lo que no valida no se firma: un descriptor incompleto es un defecto del
// release que debe reventar al CONSTRUIR, no al cargar en la máquina de un
// usuario.
func Firmar(m *Manifest, priv ed25519.PrivateKey) (manifestJSON, firma []byte, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("%w: clave privada de %d bytes, se esperan %d",
			ErrClaveInvalida, len(priv), ed25519.PrivateKeySize)
	}
	if err := m.validar(); err != nil {
		return nil, nil, fmt.Errorf("no se firma un manifiesto inválido: %w", err)
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("manifest: no se pudo serializar: %w", err)
	}
	return b, ed25519.Sign(priv, b), nil
}
