package dpapi

import (
	"bytes"
	"testing"
)

func TestIdaYVuelta(t *testing.T) {
	secreto := []byte("clave-de-release-de-prueba-0123456789")
	cifrado, err := Proteger(secreto, nil)
	if err != nil {
		t.Fatalf("Proteger: %v", err)
	}
	if bytes.Contains(cifrado, secreto) {
		t.Fatal("el cifrado contiene el secreto en claro")
	}
	claro, err := Desproteger(cifrado, nil)
	if err != nil {
		t.Fatalf("Desproteger: %v", err)
	}
	if !bytes.Equal(claro, secreto) {
		t.Fatalf("ida y vuelta corrompió el secreto: %q", claro)
	}
}

func TestEntropiaEquivocadaFalla(t *testing.T) {
	cifrado, err := Proteger([]byte("secreto"), []byte("entropia-buena"))
	if err != nil {
		t.Fatalf("Proteger: %v", err)
	}
	if _, err := Desproteger(cifrado, []byte("entropia-mala")); err == nil {
		t.Fatal("desproteger con entropía distinta debía fallar y no falló")
	}
	if _, err := Desproteger(cifrado, nil); err == nil {
		t.Fatal("desproteger sin entropía debía fallar y no falló")
	}
}

func TestBasuraFalla(t *testing.T) {
	if _, err := Desproteger([]byte("esto no es un blob DPAPI"), nil); err == nil {
		t.Fatal("desproteger basura debía fallar")
	}
	if _, err := Proteger(nil, nil); err == nil {
		t.Fatal("proteger nada debía fallar")
	}
}
