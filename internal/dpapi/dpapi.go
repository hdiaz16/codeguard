// Package dpapi cifra secretos en reposo con la Data Protection API de
// Windows, atados a la cuenta del usuario: un archivo protegido aquí no se
// puede abrir desde otra cuenta ni copiado a otra máquina, y no hay
// passphrase que administrar ni olvidar. Es el guardado elegido para la
// clave privada de release (W3, decisión de Héctor 2026-08-23: el release es
// local, la clave vive local — ver docs/threat-model-rulepack.md).
package dpapi

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData = crypt32.NewProc("CryptProtectData")
	procCryptUnprotect   = crypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func blobDe(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func (b dataBlob) bytes() []byte {
	if b.pbData == nil || b.cbData == 0 {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

// Proteger cifra data con DPAPI en ámbito de USUARIO (CRYPTPROTECT_UI_FORBIDDEN:
// jamás un diálogo — esto corre en herramientas de línea de comandos). La
// entropía adicional es un segundo factor opcional que debe repetirse al
// desproteger; vacía significa solo la cuenta de Windows.
func Proteger(data, entropia []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("dpapi: nada que proteger")
	}
	in := blobDe(data)
	ent := blobDe(entropia)
	var out dataBlob
	// CRYPTPROTECT_UI_FORBIDDEN = 0x1
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&ent)),
		0, 0, 0x1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, fmt.Errorf("dpapi: CryptProtectData falló: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData))) //nolint:errcheck
	return out.bytes(), nil
}

// Desproteger descifra lo que Proteger cifró, con la MISMA entropía. Falla
// (fail-closed, sin adivinar) desde otra cuenta, otra máquina o con entropía
// distinta.
func Desproteger(data, entropia []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("dpapi: nada que desproteger")
	}
	in := blobDe(data)
	ent := blobDe(entropia)
	var out dataBlob
	r, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&ent)),
		0, 0, 0x1, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return nil, fmt.Errorf("dpapi: CryptUnprotectData falló (¿otra cuenta/máquina o entropía distinta?): %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData))) //nolint:errcheck
	return out.bytes(), nil
}
