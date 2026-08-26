// Package manifest implementa la verificación criptográfica (Ed25519 +
// SHA256) del manifiesto de rulepack: la lista exacta de archivos con sus
// hashes y el digest del árbol, firmada por una clave de release.
//
// Doctrina fail-closed firmada por el consejo (plan-calidad-mundial, turnos
// 95-104): lo que no se puede verificar se RECHAZA con un error que dice por
// qué — una clave malformada, una firma truncada o un descriptor incompleto
// jamás se interpretan como "no hace falta verificar".
//
// La firma cubre BYTES, no contenido lógico: FirmarRulepack serializa una vez
// y esos bytes exactos son los que se escriben a disco y los que se
// verifican. Re-serializar (aunque el JSON sea equivalente) invalida la
// firma, y eso es correcto: el manifiesto se escribe UNA vez y nunca se
// reformatea.
//
// Hasta la limpieza de 2026-08-25 este paquete llevaba además un verificador
// de BINARIOS DE MOTORES (Manifest, EngineDescriptor, CargarYVerificar,
// VerificarBinario y su caché de hashes). Aquella distribución la sustituyó
// la de rulepacks de W3 y quedó sin un solo consumidor: ninguna de sus
// funciones era alcanzable desde ningún main, y solo la sostenían sus propios
// tests. Se retiró entera. Si algún día vuelve a hacer falta verificar
// binarios sueltos, se diseña con lo que se sepa entonces, no resucitando
// esto.
package manifest

import "errors"

var (
	ErrFirmaInvalida    = errors.New("manifest: firma criptográfica Ed25519 inválida")
	ErrFirmaMalformada  = errors.New("manifest: firma de tamaño incorrecto (truncada o corrupta, no es una firma Ed25519)")
	ErrClaveInvalida    = errors.New("manifest: clave pública de tamaño incorrecto — sin clave válida no hay verificación posible")
	ErrClaveDesconocida = errors.New("manifest: signer_key_id no corresponde a ninguna clave de release conocida")
	ErrManifestVacio    = errors.New("manifest: manifiesto vacío o corrupto")
	ErrManifestInvalido = errors.New("manifest: contenido estructuralmente inválido")
)
