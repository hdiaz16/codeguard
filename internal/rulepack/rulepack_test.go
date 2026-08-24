package rulepack

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/manifest"
)

// crearPack fabrica un rulepack mínimo pero REAL (con un archivo de reglas):
// un directorio vacío ya no resuelve — sin un solo archivo no hay identidad.
func crearPack(t *testing.T, base, version string) string {
	t.Helper()
	dir := filepath.Join(base, "rulepacks", version)
	if err := os.MkdirAll(filepath.Join(dir, "semgrep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "semgrep", "reglas.yaml"), []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// El rulepack se resuelve en cuatro sitios y el orden importa. Lo vendoreado en
// el repo es el RESPALDO, no la preferencia: se usa cuando esa versión no está
// instalada, y pierde contra ella cuando lo está.
//
// La versión anterior de este contrato decía lo contrario, y el contrario era
// explotable: mientras el repo analizado ganaba, bastaba traer un
// `rulepacks/<la versión que pinnea>/` con reglas de relleno para que las de
// la casa no llegaran a mirar el código. Medido con el mismo archivo y una
// inyección SQL de manual: BLOQUEADO con el rulepack instalado, "commit
// permitido" con el del repo. Sin carrera y sin atacante sofisticado: basta
// clonar el repositorio. (El comando `ci` conservó una copia inlineada con el
// orden viejo hasta 2026-08-23 — por eso la resolución ahora es ÚNICA.)
func TestResolverPrefiereLoInstaladoSobreLoVendoreado(t *testing.T) {
	repo := t.TempDir()
	instalacion := t.TempDir()
	t.Setenv("LOCALAPPDATA", instalacion)

	// Sólo la instalación estándar lo tiene: ahí debe encontrarlo.
	instalado := crearPack(t, filepath.Join(instalacion, "CodeGuard"), "2026.08.2")
	id, err := Resolver(repo, "2026.08.2")
	if err != nil || id.Path != instalado || id.Source != SourceInstalled {
		t.Errorf("con el pack sólo en la instalación estándar: id=%+v err=%v, quería Path=%s Source=installed", id, err, instalado)
	}
	if id.Digest == "" {
		t.Error("la identidad resuelta debe traer digest")
	}

	// Y ahora el repo trae el SUYO con el mismo número. El mismo número
	// nombrando dos artefactos distintos es una colisión, y en una colisión gana
	// el de la organización: la versión es una promesa de paridad con el CI, y
	// quien analiza no puede dejar que el analizado elija con qué se le mide.
	crearPack(t, repo, "2026.08.2")
	id, err = Resolver(repo, "2026.08.2")
	if err != nil || id.Path != instalado {
		t.Errorf("el repo analizado NO puede imponer sus reglas sobre las instaladas: id=%+v err=%v", id, err)
	}

	// Con una versión que sólo está vendoreada, el respaldo entra: es el caso
	// que justificó la cadena y no puede romperse. Y se DICE (Source).
	soloEnElRepo := crearPack(t, repo, "2026.09.9")
	id, err = Resolver(repo, "2026.09.9")
	if err != nil || id.Path != soloEnElRepo || id.Source != SourceVendored {
		t.Errorf("una versión que sólo está vendoreada tiene que usarse y anunciarse: id=%+v err=%v", id, err)
	}

	// Una versión que no está en ningún sitio: ErrNoEncontrado, y la identidad
	// apunta a la ruta del repo para que el mensaje hable de donde el dev
	// PODRÍA vendorearla.
	id, err = Resolver(repo, "2099.01.1")
	if !errors.Is(err, ErrNoEncontrado) {
		t.Errorf("sin candidatos debía dar ErrNoEncontrado, got: %v", err)
	}
	if quiere := filepath.Join(repo, "rulepacks", "2099.01.1"); id.Path != quiere {
		t.Errorf("sin candidatos la identidad apunta al repo:\n  got  %s\n  want %s", id.Path, quiere)
	}
}

// Un instalado PRESENTE pero inválido jamás cae en silencio al vendoreado
// (t.103): caer sería dejar que romper el instalado elija las reglas del repo.
func TestUnInstaladoRotoNoCaeAlVendoreado(t *testing.T) {
	repo := t.TempDir()
	instalacion := t.TempDir()
	t.Setenv("LOCALAPPDATA", instalacion)

	// El instalado existe pero está VACÍO (sin un solo archivo = sin identidad).
	if err := os.MkdirAll(filepath.Join(instalacion, "CodeGuard", "rulepacks", "2026.08.2"), 0o755); err != nil {
		t.Fatal(err)
	}
	// El repo trae uno perfectamente válido con el mismo número.
	crearPack(t, repo, "2026.08.2")

	id, err := Resolver(repo, "2026.08.2")
	if err == nil || errors.Is(err, ErrNoEncontrado) {
		t.Fatalf("un instalado roto debía dar error propio, got: %v", err)
	}
	if id.Source != SourceInstalled {
		t.Errorf("el candidato elegido no cambia por estar roto: Source=%s", id.Source)
	}
	if id.Digest != "" {
		t.Error("sin árbol válido no hay digest que prometer")
	}
}

func TestRulepacksInstaladosVeLaInstalacionEstandar(t *testing.T) {
	repo := t.TempDir()
	instalacion := t.TempDir()
	t.Setenv("LOCALAPPDATA", instalacion)
	for _, v := range []string{"2026.08.2", "2026.09.1"} {
		if err := os.MkdirAll(filepath.Join(instalacion, "CodeGuard", "rulepacks", v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := RulepacksInstalados(repo)
	// Orden: de más nueva a más vieja.
	if len(got) != 2 || got[0] != "2026.09.1" || got[1] != "2026.08.2" {
		t.Fatalf("instaladas = %v, esperaba [2026.09.1 2026.08.2]", got)
	}
}

// ── El digest de árbol: qué lo cambia, qué no, y qué lo invalida ─────────────

func TestDigestArbolDetectaCadaClaseDeAdulteracion(t *testing.T) {
	dir := t.TempDir()
	escribir := func(rel, contenido string) {
		t.Helper()
		ruta := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ruta, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribir("semgrep/a.yaml", "rules: [a]\n")
	escribir("semgrep/b.yaml", "rules: [b]\n")
	escribir("VERSION", "2026.08.2\n")

	base, err := DigestArbol(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Dos árboles byte-idénticos ⇒ mismo digest (la propiedad de paridad).
	copia := t.TempDir()
	for _, rel := range []string{"semgrep/a.yaml", "semgrep/b.yaml", "VERSION"} {
		raw, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		ruta := filepath.Join(copia, filepath.FromSlash(rel))
		_ = os.MkdirAll(filepath.Dir(ruta), 0o755)
		_ = os.WriteFile(ruta, raw, 0o644)
	}
	if d2, err := DigestArbol(copia); err != nil || d2 != base {
		t.Errorf("copia byte-idéntica debía dar el mismo digest: %s vs %s (err=%v)", d2, base, err)
	}

	// Bit-flip en un contenido.
	escribir("semgrep/a.yaml", "rules: [X]\n")
	if d, _ := DigestArbol(dir); d == base {
		t.Error("bit-flip en una regla no cambió el digest")
	}
	escribir("semgrep/a.yaml", "rules: [a]\n")

	// Flip de EOL: es un cambio REAL de bytes y se nota (veto de GPT t.103 a
	// normalizar: la identidad autentica lo distribuido).
	escribir("semgrep/a.yaml", "rules: [a]\r\n")
	if d, _ := DigestArbol(dir); d == base {
		t.Error("flip LF→CRLF no cambió el digest y debía")
	}
	escribir("semgrep/a.yaml", "rules: [a]\n")

	// Archivo extra.
	escribir("semgrep/z.yaml", "rules: [z]\n")
	if d, _ := DigestArbol(dir); d == base {
		t.Error("un archivo extra no cambió el digest")
	}
	if err := os.Remove(filepath.Join(dir, "semgrep", "z.yaml")); err != nil {
		t.Fatal(err)
	}

	// Archivo ausente.
	if err := os.Remove(filepath.Join(dir, "VERSION")); err != nil {
		t.Fatal(err)
	}
	if d, _ := DigestArbol(dir); d == base {
		t.Error("un archivo ausente no cambió el digest")
	}
	escribir("VERSION", "2026.08.2\n")

	// Lo verificado al final tiene que seguir siendo lo de la base.
	if d, err := DigestArbol(dir); err != nil || d != base {
		t.Fatalf("el árbol restaurado debía volver al digest base (d=%s err=%v)", d, err)
	}

	// testdata NO entra (no se distribuye: build-dist lo poda del instalador);
	// hashearlo haría divergir repo↔instalado con reglas IDÉNTICAS.
	escribir("testdata/fixture.sql", "DROP TABLE x;\n")
	if d, _ := DigestArbol(dir); d != base {
		t.Error("testdata entró al digest y no debía")
	}

	// manifest.json/.sig en la raíz NO entran (autorreferencia: firman el árbol).
	escribir("manifest.json", "{}")
	escribir("manifest.sig", "xx")
	if d, _ := DigestArbol(dir); d != base {
		t.Error("manifest.json/.sig entraron al digest y no debían")
	}
}

func TestDigestArbolFailClosed(t *testing.T) {
	// Árbol sin un solo archivo: sin identidad.
	if _, err := DigestArbol(t.TempDir()); !errors.Is(err, ErrArbolInvalido) {
		t.Errorf("árbol vacío debía dar ErrArbolInvalido, got: %v", err)
	}

	// Colisión case-insensitive entre rutas: ambigüedad, se rechaza entera.
	// (Solo se puede fabricar en un filesystem case-sensitive; en NTFS los dos
	// nombres serían el mismo archivo, así que si la escritura los fusiona el
	// caso no aplica y se salta.)
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "semgrep"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "semgrep", "a.yaml"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "semgrep", "A.yaml"), []byte("y"), 0o644)
	if entradas, _ := os.ReadDir(filepath.Join(dir, "semgrep")); len(entradas) == 2 {
		if _, err := DigestArbol(dir); !errors.Is(err, ErrArbolInvalido) {
			t.Errorf("colisión de mayúsculas debía dar ErrArbolInvalido, got: %v", err)
		}
	}

	// Un symlink dentro del árbol es fuga o basura: rechazo con nombre.
	// (Crear symlinks en Windows exige privilegio; sin él, el caso se salta.)
	dirLink := t.TempDir()
	_ = os.WriteFile(filepath.Join(dirLink, "real.yaml"), []byte("x"), 0o644)
	fuera := filepath.Join(t.TempDir(), "fuera.yaml")
	_ = os.WriteFile(fuera, []byte("payload"), 0o644)
	if err := os.Symlink(fuera, filepath.Join(dirLink, "enlace.yaml")); err == nil {
		if _, err := DigestArbol(dirLink); !errors.Is(err, ErrArbolInvalido) {
			t.Errorf("symlink dentro del árbol debía dar ErrArbolInvalido, got: %v", err)
		}
		if _, err := DigestArbol(dirLink); err == nil || !strings.Contains(err.Error(), "enlace.yaml") {
			t.Errorf("el rechazo debe nombrar la entrada culpable, got: %v", err)
		}
	} else {
		t.Logf("sin privilegio de symlink en esta máquina; caso cubierto por la revisión de tipos del walker (%v)", err)
	}
}

// ── La verificación del instalado firmado (tanda c de W3) ────────────────────

// firmarPack firma un rulepack como lo haría codeguard-release y devuelve el
// registro de claves con el que un binario lo verificaría.
func firmarPack(t *testing.T, dir, version string) map[string]ed25519.PublicKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := Inventario(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := make([]manifest.ArchivoDeRulepack, len(inv))
	for i, a := range inv {
		files[i] = manifest.ArchivoDeRulepack{Path: a.Rel, SHA256: a.SHA256, SizeBytes: a.Size}
	}
	m := &manifest.RulepackManifest{
		Schema: manifest.RulepackSchemaSoportado, Rulepack: version,
		GeneratedAt: "2026-08-23T12:00:00Z", SignerKeyID: "rel-test",
		TreeDigest: DigestDeInventario(inv), Files: files,
	}
	manifestJSON, firma, err := manifest.FirmarRulepack(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), firma, 0o644); err != nil {
		t.Fatal(err)
	}
	return map[string]ed25519.PublicKey{"rel-test": pub}
}

func TestInstaladoFirmadoSeVerificaYLoAdulteradoSeRechaza(t *testing.T) {
	repo := t.TempDir()
	instalacion := t.TempDir()
	t.Setenv("LOCALAPPDATA", instalacion)
	dir := crearPack(t, filepath.Join(instalacion, "CodeGuard"), "2026.09.1")
	claves := firmarPack(t, dir, "2026.09.1")

	// Firmado y sin tocar: Verified=true.
	id, err := ResolverConClaves(repo, "2026.09.1", claves)
	if err != nil || !id.Verified {
		t.Fatalf("instalado firmado debía verificar: id=%+v err=%v", id, err)
	}

	// Bit-flip en una regla: rechazo con el archivo culpable nombrado.
	regla := filepath.Join(dir, "semgrep", "reglas.yaml")
	if err := os.WriteFile(regla, []byte("rules: [ADULTERADA]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ResolverConClaves(repo, "2026.09.1", claves)
	if err == nil || !strings.Contains(err.Error(), "semgrep/reglas.yaml") {
		t.Fatalf("bit-flip debía rechazar nombrando el archivo, got: %v", err)
	}
	if err := os.WriteFile(regla, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Archivo extra tras la firma: rechazo que lo nombra.
	extra := filepath.Join(dir, "semgrep", "colada.yaml")
	if err := os.WriteFile(extra, []byte("rules: [x]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ResolverConClaves(repo, "2026.09.1", claves)
	if err == nil || !strings.Contains(err.Error(), "colada.yaml") {
		t.Fatalf("archivo colado debía rechazar nombrándolo, got: %v", err)
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}

	// Firma de OTRA clave (registro que no la conoce): rechazo.
	otras := firmarPack(t, dir, "2026.09.1") // re-firma con clave nueva
	if _, err := ResolverConClaves(repo, "2026.09.1", claves); err == nil {
		t.Fatal("manifiesto de clave desconocida debía rechazar")
	}
	if id, err := ResolverConClaves(repo, "2026.09.1", otras); err != nil || !id.Verified {
		t.Fatalf("con SU registro debía verificar: %v", err)
	}
}

// El misbinding medido en esta máquina (dos contenidos, un nombre): copiar un
// rulepack COMPLETO y firmado sobre un directorio con otro nombre rechaza —
// la versión viaja DENTRO de lo firmado.
func TestReplayDeOtraVersionRechaza(t *testing.T) {
	repo := t.TempDir()
	instalacion := t.TempDir()
	t.Setenv("LOCALAPPDATA", instalacion)
	dir := crearPack(t, filepath.Join(instalacion, "CodeGuard"), "2026.10.1")
	claves := firmarPack(t, dir, "2026.07.1") // firmado como la versión VIEJA

	_, err := ResolverConClaves(repo, "2026.10.1", claves)
	if err == nil || !strings.Contains(err.Error(), "misbinding") {
		t.Fatalf("replay de versión debía rechazar por misbinding, got: %v", err)
	}
}

// Sin claves embebidas no se puede exigir firma: el instalado carga con
// Verified=false y SIN error — la exigencia nace con el primer binario que
// embeba una clave, jamás antes.
func TestSinClavesNoSeExigeYNoSeMiente(t *testing.T) {
	repo := t.TempDir()
	instalacion := t.TempDir()
	t.Setenv("LOCALAPPDATA", instalacion)
	crearPack(t, filepath.Join(instalacion, "CodeGuard"), "2026.09.2")

	id, err := ResolverConClaves(repo, "2026.09.2", nil)
	if err != nil {
		t.Fatalf("sin claves no hay exigencia posible: %v", err)
	}
	if id.Verified {
		t.Fatal("Verified=true sin haber verificado firma alguna: el campo mintió")
	}

	// Y el instalado firmado SIN claves tampoco miente Verified.
	firmarPack(t, id.Path, "2026.09.2")
	id, err = ResolverConClaves(repo, "2026.09.2", nil)
	if err != nil || id.Verified {
		t.Fatalf("con firma pero sin registro, Verified debe seguir false: id=%+v err=%v", id, err)
	}
}

// El vendoreado JAMÁS exige firma (las reglas del propio equipo no tienen
// nuestra clave) — aunque el binario lleve claves embebidas.
func TestVendoreadoNoExigeFirmaAunConClaves(t *testing.T) {
	repo := t.TempDir()
	instalacion := t.TempDir()
	t.Setenv("LOCALAPPDATA", instalacion)
	crearPack(t, repo, "2026.09.3")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	id, err := ResolverConClaves(repo, "2026.09.3", map[string]ed25519.PublicKey{"rel-x": pub})
	if err != nil {
		t.Fatalf("vendoreado sin manifiesto debía cargar: %v", err)
	}
	if id.Source != SourceVendored || id.Verified {
		t.Fatalf("vendoreado: Source=%s Verified=%v, esperaba vendored/false", id.Source, id.Verified)
	}
}
