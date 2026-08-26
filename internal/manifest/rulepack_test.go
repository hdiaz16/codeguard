package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Estas pruebas existen por una razón concreta: al retirar el verificador de
// BINARIOS de este paquete se fueron con él los únicos tests que ejercían la
// matriz fail-closed a nivel de unidad — firma truncada, manifiesto vacío,
// JSON con campos desconocidos, datos tras el primer valor. Esa matriz estaba
// probada contra la función MUERTA y no contra la viva.
//
// Los tests de internal/rulepack cubren de punta a punta la adulteración, el
// archivo colado, la clave desconocida y el replay de versión, pero pasan por
// el resolutor y asertan sobre el texto del error. Aquí se fija el CONTRATO
// de CargarYVerificarRulepack: qué error centinela sale por cada forma de
// romperlo, y en qué ORDEN se comprueba (la firma ANTES del parseo: nunca se
// interpreta un documento cuya autoría no está probada).
func manifiestoValido(keyID string) *RulepackManifest {
	return &RulepackManifest{
		Schema:      RulepackSchemaSoportado,
		Rulepack:    "2026.09.1",
		GeneratedAt: "2026-09-01T00:00:00Z",
		SignerKeyID: keyID,
		TreeDigest:  strings.Repeat("ab", 32),
		Files: []ArchivoDeRulepack{
			{Path: "semgrep/reglas.yaml", SHA256: strings.Repeat("cd", 32), SizeBytes: 12},
		},
	}
}

func TestRulepackFirmadoValidoSeVerifica(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claves := map[string]ed25519.PublicKey{"k1": pub}

	manifestJSON, firma, err := FirmarRulepack(manifiestoValido("k1"), priv)
	if err != nil {
		t.Fatalf("un manifiesto válido debía firmarse: %v", err)
	}
	m, err := CargarYVerificarRulepack(manifestJSON, firma, claves)
	if err != nil {
		t.Fatalf("lo recién firmado debía verificar: %v", err)
	}
	if m.Rulepack != "2026.09.1" {
		t.Errorf("rulepack = %q", m.Rulepack)
	}
}

func TestRulepackFailClosed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claves := map[string]ed25519.PublicKey{"k1": pub}
	bueno, firmaBuena, err := FirmarRulepack(manifiestoValido("k1"), priv)
	if err != nil {
		t.Fatal(err)
	}

	// Firmar bytes arbitrarios con la clave buena: sirve para probar que lo
	// que rechaza es el PARSEO estricto y no la firma.
	firmarCrudo := func(b []byte) []byte { return ed25519.Sign(priv, b) }

	casos := []struct {
		nombre   string
		manifest []byte
		firma    []byte
		esperado error
	}{
		{
			nombre:   "manifiesto vacío",
			manifest: nil,
			firma:    firmaBuena,
			esperado: ErrManifestVacio,
		},
		{
			nombre:   "firma truncada",
			manifest: bueno,
			firma:    firmaBuena[:len(firmaBuena)-1],
			esperado: ErrFirmaMalformada,
		},
		{
			nombre:   "firma de otra clave",
			manifest: bueno,
			firma:    firmaFalsa(t, bueno),
			esperado: ErrFirmaInvalida,
		},
		{
			nombre:   "campo JSON desconocido (firmado)",
			manifest: conCampoExtra(t, bueno),
			firma:    firmarCrudo(conCampoExtra(t, bueno)),
			esperado: ErrManifestInvalido,
		},
		{
			nombre:   "datos tras el primer valor JSON (firmados)",
			manifest: append(append([]byte{}, bueno...), []byte("\n{}")...),
			firma:    firmarCrudo(append(append([]byte{}, bueno...), []byte("\n{}")...)),
			esperado: ErrManifestInvalido,
		},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			_, err := CargarYVerificarRulepack(c.manifest, c.firma, claves)
			if !errors.Is(err, c.esperado) {
				t.Fatalf("se esperaba %v, salió: %v", c.esperado, err)
			}
		})
	}

	// El signer_key_id manda a QUÉ clave se consulta: un id que el registro no
	// conoce se rechaza ANTES de mirar la firma. Un registro vacío rechaza
	// todo, que es el fail-closed que W3 vino a fijar.
	if _, err := CargarYVerificarRulepack(bueno, firmaBuena, map[string]ed25519.PublicKey{}); !errors.Is(err, ErrClaveDesconocida) {
		t.Fatalf("registro sin la clave debía dar ErrClaveDesconocida, salió: %v", err)
	}

	// Una clave registrada pero de tamaño imposible es material corrupto, no
	// una invitación a saltarse la verificación.
	corrupto := map[string]ed25519.PublicKey{"k1": ed25519.PublicKey("demasiado corta")}
	if _, err := CargarYVerificarRulepack(bueno, firmaBuena, corrupto); !errors.Is(err, ErrClaveInvalida) {
		t.Fatalf("clave de tamaño incorrecto debía dar ErrClaveInvalida, salió: %v", err)
	}
}

func TestNoSeFirmaUnManifiestoInvalido(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	malos := map[string]func(*RulepackManifest){
		"schema desconocido":        func(m *RulepackManifest) { m.Schema = 99 },
		"versión vacía":             func(m *RulepackManifest) { m.Rulepack = "" },
		"tree_digest en mayúsculas": func(m *RulepackManifest) { m.TreeDigest = strings.ToUpper(m.TreeDigest) },
		"ruta que se sale":          func(m *RulepackManifest) { m.Files[0].Path = "../fuera.yaml" },
		"sin archivos":              func(m *RulepackManifest) { m.Files = nil },
	}
	for nombre, romper := range malos {
		t.Run(nombre, func(t *testing.T) {
			m := manifiestoValido("k1")
			romper(m)
			if _, _, err := FirmarRulepack(m, priv); err == nil {
				t.Fatal("un manifiesto inválido jamás debe firmarse")
			}
		})
	}
}

func firmaFalsa(t *testing.T, b []byte) []byte {
	t.Helper()
	_, otra, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.Sign(otra, b)
}

func conCampoExtra(t *testing.T, manifestJSON []byte) []byte {
	t.Helper()
	var libre map[string]any
	if err := json.Unmarshal(manifestJSON, &libre); err != nil {
		t.Fatal(err)
	}
	libre["campo_que_este_binario_no_conoce"] = "colado"
	b, err := json.Marshal(libre)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
