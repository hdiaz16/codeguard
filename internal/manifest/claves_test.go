package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestParsearClavesDeReleaseVacioSoloParaDesarrollo(t *testing.T) {
	claves, err := ParsearClavesDeRelease("")
	if err != nil || len(claves) != 0 {
		t.Fatalf("registro de desarrollo vacío: claves=%d err=%v", len(claves), err)
	}
}

func TestParsearClavesDeReleaseValidaIdentidadYPublica(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	suma := sha256.Sum256(pub)
	id := "rel-" + hex.EncodeToString(suma[:4])
	valor := id + "=" + hex.EncodeToString(pub)

	claves, err := ParsearClavesDeRelease(valor)
	if err != nil {
		t.Fatal(err)
	}
	if got := claves[id]; !got.Equal(pub) {
		t.Fatal("la pública parseada no coincide")
	}
}

func TestParsearClavesDeReleaseRechazaMisbindingDuplicadosYFormato(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	suma := sha256.Sum256(pub)
	id := "rel-" + hex.EncodeToString(suma[:4])
	entrada := id + "=" + hex.EncodeToString(pub)
	casos := map[string]string{
		"id ajeno":  "rel-00000000=" + hex.EncodeToString(pub),
		"duplicada": entrada + "," + entrada,
		"espacios":  " " + entrada,
		"hex corto": id + "=abcd",
		"sin igual": id,
	}
	for nombre, valor := range casos {
		t.Run(nombre, func(t *testing.T) {
			if _, err := ParsearClavesDeRelease(valor); err == nil {
				t.Fatal("el registro inválido fue aceptado")
			}
		})
	}
}
