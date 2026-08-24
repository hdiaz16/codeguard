package attest_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeguard/internal/attest"
	"codeguard/internal/manifest"
)

// ============================================================================
// HELPERS DE INFRAESTRUCTURA GIT HERMÉTICOS (REPOSITORIO REAL, SIN MOCKS)
// ============================================================================

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=CodeGuard E2E",
		"GIT_AUTHOR_EMAIL=e2e@codeguard.test",
		"GIT_COMMITTER_NAME=CodeGuard E2E",
		"GIT_COMMITTER_EMAIL=e2e@codeguard.test",
		"GIT_CONFIG_NOSYSTEM=1",
		"HOME="+dir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s falló: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func initRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git no disponible en PATH")
	}
	dir := t.TempDir()
	runGit(t, dir, "init", "-b", "main")
	return dir
}

func writeAndStage(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", name)
}

func treeSHA(t *testing.T, dir string) string {
	t.Helper()
	return runGit(t, dir, "write-tree")
}

func commitWithMessage(t *testing.T, dir, msg string) string {
	t.Helper()
	runGit(t, dir, "commit", "--cleanup=verbatim", "-m", msg)
	return runGit(t, dir, "rev-parse", "HEAD")
}

func commitMessage(t *testing.T, dir, rev string) string {
	t.Helper()
	return runGit(t, dir, "log", "-1", "--format=%B", rev)
}

const (
	strongPolicyHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	weakPolicyHash   = "0000000000000000000000000000000000000000000000000000000000000000"
	testMaxAge       = 10 * time.Minute
)

// ============================================================================
// ESCENARIO 1: FLUJO LEGÍTIMO E2E (HAPPY PATH)
// ============================================================================
func TestE2E_FlujoLegitimo(t *testing.T) {
	dir := initRepo(t)

	signer, err := attest.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	verifier := attest.NewEd25519Verifier(signer.PublicKey())

	writeAndStage(t, dir, "main.go", "package main\n\nfunc main() {}\n")
	tree := treeSHA(t, dir)

	now := time.Now().UTC()
	claims := attest.Claims{
		Version:    attest.Version,
		TreeSHA:    tree,
		PolicyHash: strongPolicyHash,
		RepoID:     "empresa-ejemplo-mx/demo.codeguard",
		Timestamp:  now.Unix(),
	}

	att, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	encoded, err := att.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	commitMsgOriginal := "feat: implementar servicio de pagos seguro"
	commitMsgConTrailer, err := attest.InjectTrailer(commitMsgOriginal, encoded)
	if err != nil {
		t.Fatalf("InjectTrailer: %v", err)
	}

	head := commitWithMessage(t, dir, commitMsgConTrailer)

	msgLeido := commitMessage(t, dir, head)
	rawTrailer, err := attest.ExtractTrailer(msgLeido)
	if err != nil {
		t.Fatalf("ExtractTrailer falló en commit %s: %v", head, err)
	}

	attExtraida, err := attest.Decode(rawTrailer)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	opts := attest.VerifyOptions{
		ExpectedTreeSHA:    tree,
		ExpectedPolicyHash: strongPolicyHash,
		MaxAge:             testMaxAge,
		Now:                now,
	}

	if err := verifier.Verify(attExtraida, opts); err != nil {
		t.Fatalf("Verificación de commit legítimo falló inesperadamente: %v", err)
	}
}

// ============================================================================
// ESCENARIO 2: ATAQUE DE BYPASS (git commit --no-verify) -> RECHAZADO
// ============================================================================
func TestE2E_AtaqueBypass_NoVerify(t *testing.T) {
	dir := initRepo(t)

	writeAndStage(t, dir, "evil.go", "package main\n// bypass flag --no-verify\n")
	head := commitWithMessage(t, dir, "feat: cambio saltándose hooks con --no-verify")

	msgLeido := commitMessage(t, dir, head)
	_, err := attest.ExtractTrailer(msgLeido)
	if !errors.Is(err, attest.ErrNoAttestation) {
		t.Fatalf("ExtractTrailer debía retornar ErrNoAttestation, got: %v", err)
	}
}

// ============================================================================
// ESCENARIO 3: ATAQUE DE REPLAY (copiar firma de commit A a commit B) -> RECHAZADO
// ============================================================================
func TestE2E_AtaqueReplay_TreeMismatch(t *testing.T) {
	dir := initRepo(t)

	signer, err := attest.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	verifier := attest.NewEd25519Verifier(signer.PublicKey())

	// Commit A: Código limpio
	writeAndStage(t, dir, "limpio.go", "package main\n")
	treeA := treeSHA(t, dir)

	claimsA := attest.Claims{
		Version:    attest.Version,
		TreeSHA:    treeA,
		PolicyHash: strongPolicyHash,
		Timestamp:  time.Now().UTC().Unix(),
	}
	attA, _ := signer.Sign(claimsA)
	encodedA, _ := attA.Encode()

	// Commit B: Código malicioso con trailer robado de A
	writeAndStage(t, dir, "malicioso.go", "package main\nimport \"os/exec\"\nfunc init() { exec.Command(\"rm\", \"-rf\").Run() }\n")
	treeB := treeSHA(t, dir)

	msgAtacante, _ := attest.InjectTrailer("feat: cambio malicioso", encodedA)
	headB := commitWithMessage(t, dir, msgAtacante)

	msgB := commitMessage(t, dir, headB)
	rawB, err := attest.ExtractTrailer(msgB)
	if err != nil {
		t.Fatalf("ExtractTrailer falló: %v", err)
	}
	attExtraida, _ := attest.Decode(rawB)

	opts := attest.VerifyOptions{
		ExpectedTreeSHA:    treeB,
		ExpectedPolicyHash: strongPolicyHash,
		MaxAge:             testMaxAge,
	}

	err = verifier.Verify(attExtraida, opts)
	if !errors.Is(err, attest.ErrTreeMismatch) {
		t.Fatalf("Ataque de Replay debía ser rechazado con ErrTreeMismatch, got: %v", err)
	}
}

// ============================================================================
// ESCENARIO 4: ATAQUE DE DOWNGRADE (política debilitada) -> RECHAZADO
// ============================================================================
func TestE2E_AtaqueDowngrade_PolicyMismatch(t *testing.T) {
	dir := initRepo(t)

	signer, _ := attest.GenerateSigner()
	verifier := attest.NewEd25519Verifier(signer.PublicKey())

	writeAndStage(t, dir, "main.go", "package main\n")
	tree := treeSHA(t, dir)

	claimsDebil := attest.Claims{
		Version:    attest.Version,
		TreeSHA:    tree,
		PolicyHash: weakPolicyHash,
		Timestamp:  time.Now().UTC().Unix(),
	}
	attDebil, _ := signer.Sign(claimsDebil)
	encoded, _ := attDebil.Encode()

	msg, _ := attest.InjectTrailer("feat: downgrade", encoded)
	head := commitWithMessage(t, dir, msg)

	msgLeido := commitMessage(t, dir, head)
	rawTrailer, _ := attest.ExtractTrailer(msgLeido)
	attExtraida, _ := attest.Decode(rawTrailer)

	opts := attest.VerifyOptions{
		ExpectedTreeSHA:    tree,
		ExpectedPolicyHash: strongPolicyHash,
		MaxAge:             testMaxAge,
	}

	err := verifier.Verify(attExtraida, opts)
	if !errors.Is(err, attest.ErrPolicyMismatch) {
		t.Fatalf("Ataque de Downgrade debía ser rechazado con ErrPolicyMismatch, got: %v", err)
	}
}

// ============================================================================
// ESCENARIO 5: ATAQUE DE MANIPULACIÓN DE FIRMA (Bit Flip) -> RECHAZADO
// ============================================================================
func TestE2E_AtaqueManipulacionFirma(t *testing.T) {
	signer, _ := attest.GenerateSigner()
	verifier := attest.NewEd25519Verifier(signer.PublicKey())

	claims := attest.Claims{
		Version:    attest.Version,
		TreeSHA:    "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		PolicyHash: strongPolicyHash,
		Timestamp:  time.Now().UTC().Unix(),
	}
	att, _ := signer.Sign(claims)

	sigBytes, _ := base64.RawURLEncoding.DecodeString(att.Signature)
	sigBytes[0] ^= 0xFF
	att.Signature = base64.RawURLEncoding.EncodeToString(sigBytes)

	opts := attest.VerifyOptions{
		ExpectedTreeSHA:    claims.TreeSHA,
		ExpectedPolicyHash: strongPolicyHash,
		MaxAge:             testMaxAge,
	}

	err := verifier.Verify(att, opts)
	if !errors.Is(err, attest.ErrBadSignature) {
		t.Fatalf("Firma alterada debía ser rechazada con ErrBadSignature, got: %v", err)
	}
}

// ============================================================================
// ESCENARIO 6: ATESTACIÓN EXPIRADA -> RECHAZADA
// ============================================================================
func TestE2E_AtestacionExpirada(t *testing.T) {
	signer, _ := attest.GenerateSigner()
	verifier := attest.NewEd25519Verifier(signer.PublicKey())

	haceTresHoras := time.Now().UTC().Add(-3 * time.Hour)
	claims := attest.Claims{
		Version:    attest.Version,
		TreeSHA:    "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		PolicyHash: strongPolicyHash,
		Timestamp:  haceTresHoras.Unix(),
	}
	att, _ := signer.Sign(claims)

	opts := attest.VerifyOptions{
		ExpectedTreeSHA:    claims.TreeSHA,
		ExpectedPolicyHash: strongPolicyHash,
		MaxAge:             1 * time.Hour,
		Now:                time.Now().UTC(),
	}

	err := verifier.Verify(att, opts)
	if !errors.Is(err, attest.ErrExpired) {
		t.Fatalf("Atestación antigua debía ser rechazada con ErrExpired, got: %v", err)
	}
}

// ============================================================================
// ESCENARIO 7: MANIFIESTO DE BINARIOS — DETECCIÓN DE SUPLANTACIÓN
// ============================================================================
func TestE2E_Manifest_TamperDetection(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "gosec.exe")

	contenidoReal := []byte("binario-gosec-oficial-compilado-v2.18.0")
	if err := os.WriteFile(binPath, contenidoReal, 0o755); err != nil {
		t.Fatal(err)
	}

	hashReal := sha256.Sum256(contenidoReal)
	tamanoReal := int64(len(contenidoReal))
	desc := manifest.EngineDescriptor{
		ID:        "gosec",
		Version:   "2.18.0",
		SHA256:    hex.EncodeToString(hashReal[:]),
		SizeBytes: &tamanoReal,
	}

	ctx := t.Context()

	if err := manifest.VerificarBinario(ctx, binPath, desc); err != nil {
		t.Fatalf("VerificarBinario falló con binario legítimo: %v", err)
	}

	contenidoMalicioso := []byte("binario-gosec-modificado-con-backdoor")
	if err := os.WriteFile(binPath, contenidoMalicioso, 0o755); err != nil {
		t.Fatal(err)
	}

	err := manifest.VerificarBinario(ctx, binPath, desc)
	if err == nil {
		t.Fatal("VerificarBinario debía rechazar el binario modificado")
	}
	if !strings.Contains(err.Error(), "tamaño") && !strings.Contains(err.Error(), "hash") {
		t.Fatalf("Error inesperado en VerificarBinario: %v", err)
	}
}

// ============================================================================
// ESCENARIO 8: HOSTIL — git commit --amend INYECTANDO ARCHIVO (STALE TRAILER)
// ============================================================================
func TestE2E_Hostil_CommitAmend_StaleTrailer(t *testing.T) {
	dir := initRepo(t)

	signer, _ := attest.GenerateSigner()
	verifier := attest.NewEd25519Verifier(signer.PublicKey())

	// 1. Commit inicial legítimo y atestado
	writeAndStage(t, dir, "clean.go", "package main\n")
	tree1 := treeSHA(t, dir)

	claims1 := attest.Claims{
		Version:    attest.Version,
		TreeSHA:    tree1,
		PolicyHash: strongPolicyHash,
		Timestamp:  time.Now().UTC().Unix(),
	}
	att1, _ := signer.Sign(claims1)
	enc1, _ := att1.Encode()

	msg1, _ := attest.InjectTrailer("feat: commit inicial", enc1)
	head1 := commitWithMessage(t, dir, msg1)

	// 2. El dev hace amend agregando un archivo secreto/malicioso
	writeAndStage(t, dir, "secret.key", "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\n")
	runGit(t, dir, "commit", "--amend", "--no-edit")
	head2 := runGit(t, dir, "rev-parse", "HEAD")
	tree2 := runGit(t, dir, "rev-parse", "HEAD^{tree}")

	if head1 == head2 {
		t.Fatal("head debía cambiar tras el amend")
	}
	if tree1 == tree2 {
		t.Fatal("tree debía cambiar tras agregar secret.key")
	}

	// 3. En CI: Verificar el commit resultante del amend
	msgAmend := commitMessage(t, dir, head2)
	rawTrailer, err := attest.ExtractTrailer(msgAmend)
	if err != nil {
		t.Fatalf("ExtractTrailer falló: %v", err)
	}

	attAmend, _ := attest.Decode(rawTrailer)
	opts := attest.VerifyOptions{
		ExpectedTreeSHA:    tree2, // CI calcula el tree real del commit
		ExpectedPolicyHash: strongPolicyHash,
		MaxAge:             testMaxAge,
	}

	err = verifier.Verify(attAmend, opts)
	if !errors.Is(err, attest.ErrTreeMismatch) {
		t.Fatalf("Commit post-amend con trailer stale debía ser rechazado con ErrTreeMismatch, got: %v", err)
	}
}

// ============================================================================
// ESCENARIO 9: HOSTIL — SMUGGLED COMMIT EN RANGO DE PR (VerifyRange)
// ============================================================================
func TestE2E_Hostil_SmuggledCommit_RangeAudit(t *testing.T) {
	dir := initRepo(t)
	signer, _ := attest.GenerateSigner()
	verifier := attest.NewEd25519Verifier(signer.PublicKey())

	// Commit Base en main
	writeAndStage(t, dir, "base.txt", "base")
	baseCommit := commitWithMessage(t, dir, "feat: base commit")

	// Commit 1 (Atestado legítimo)
	writeAndStage(t, dir, "feature1.go", "package main\n")
	tree1 := treeSHA(t, dir)
	claims1 := attest.Claims{Version: attest.Version, TreeSHA: tree1, PolicyHash: strongPolicyHash, Timestamp: time.Now().UTC().Unix()}
	att1, _ := signer.Sign(claims1)
	enc1, _ := att1.Encode()
	msg1, _ := attest.InjectTrailer("feat: step 1", enc1)
	commitWithMessage(t, dir, msg1)

	// Commit 2 (CONTRABANDO / SMUGGLED: sin atestar)
	writeAndStage(t, dir, "backdoor.go", "package main\n// smuggled without hook\n")
	smuggledCommit := commitWithMessage(t, dir, "feat: smuggled commit without attest")

	// Commit 3 (Atestado legítimo)
	writeAndStage(t, dir, "feature2.go", "package main\n")
	tree3 := treeSHA(t, dir)
	claims3 := attest.Claims{Version: attest.Version, TreeSHA: tree3, PolicyHash: strongPolicyHash, Timestamp: time.Now().UTC().Unix()}
	att3, _ := signer.Sign(claims3)
	enc3, _ := att3.Encode()
	msg3, _ := attest.InjectTrailer("feat: step 3", enc3)
	headCommit := commitWithMessage(t, dir, msg3)

	// Auditar el rango de la PR: baseCommit..headCommit
	ctx := t.Context()
	opts := attest.VerifyOptions{
		ExpectedPolicyHash: strongPolicyHash,
		MaxAge:             testMaxAge,
	}

	report, err := attest.VerifyRange(ctx, dir, baseCommit, headCommit, verifier, opts)
	if err == nil {
		t.Fatal("VerifyRange debía fallar al detectar el commit de contrabando")
	}

	if report.Total != 3 {
		t.Errorf("Total = %d, want 3", report.Total)
	}
	if report.Valid != 2 {
		t.Errorf("Valid = %d, want 2", report.Valid)
	}
	if len(report.Failures) != 1 {
		t.Fatalf("Failures = %d, want 1", len(report.Failures))
	}
	if report.Failures[0].CommitSHA != smuggledCommit {
		t.Errorf("Commit reportado = %s, want %s", report.Failures[0].CommitSHA, smuggledCommit)
	}
}

// ============================================================================
// ESCENARIO 10: HOSTIL — SQUASH MERGE CON TRAILERS CONCATENADOS EN CUERPO
// ============================================================================
func TestE2E_Hostil_SquashMerge_TrailersEnCuerpo(t *testing.T) {
	// Mensaje que simula la concatenación de GitHub en un Squash Merge:
	// Contiene trailers de commits viejos en el cuerpo, seguidos de texto adicional
	msgSquashSinReatestar := `feat: squash pull request (#42)

* feat: add login
CodeGuard-Attestation: eyJ2IjoxLCJ0cmVlIjoiT0xEX1RSRUVfMSJ9

* feat: add logout
CodeGuard-Attestation: eyJ2IjoxLCJ0cmVlIjoiT0xEX1RSRUVfMiJ9

Summary of changes merged into main branch.`

	// Al terminar en prosa ("Summary of changes..."), no hay bloque final de trailers
	_, err := attest.ExtractTrailer(msgSquashSinReatestar)
	if !errors.Is(err, attest.ErrNoAttestation) {
		t.Fatalf("ExtractTrailer debía ignorar trailers en el cuerpo y retornar ErrNoAttestation, got: %v", err)
	}
}

// ============================================================================
// ESCENARIO 11: HOSTIL — INYECCIÓN DE DOBLE TRAILER (AMBIGÜEDAD)
// ============================================================================
func TestE2E_Hostil_DobleTrailer_Ambiguedad(t *testing.T) {
	msgConDobleTrailer := `feat: commit con inyección de múltiples trailers

CodeGuard-Attestation: eyJ2IjoxLCJ0cmVlIjoiVEFSR0VUX0EifQ
CodeGuard-Attestation: eyJ2IjoxLCJ0cmVlIjoiVEFSR0VUX0JifQ`

	_, err := attest.ExtractTrailer(msgConDobleTrailer)
	if !errors.Is(err, attest.ErrAmbiguousTrailer) {
		t.Fatalf("ExtractTrailer debía fallar con ErrAmbiguousTrailer, got: %v", err)
	}
}

// ============================================================================
// ESCENARIO 12: HOSTIL — CHERRY-PICK DE COMMIT A OTRA RAMA
// ============================================================================
func TestE2E_Hostil_CherryPick_CrossBranch(t *testing.T) {
	dir := initRepo(t)
	signer, _ := attest.GenerateSigner()
	verifier := attest.NewEd25519Verifier(signer.PublicKey())

	// Rama main con archivo base
	writeAndStage(t, dir, "base.txt", "main base content\n")
	commitWithMessage(t, dir, "feat: main base")

	// Crear rama feature
	runGit(t, dir, "checkout", "-b", "feature")
	writeAndStage(t, dir, "feature.go", "package main\nfunc Feature() {}\n")
	treeFeature := treeSHA(t, dir)

	claims := attest.Claims{
		Version:    attest.Version,
		TreeSHA:    treeFeature,
		PolicyHash: strongPolicyHash,
		Timestamp:  time.Now().UTC().Unix(),
	}
	att, _ := signer.Sign(claims)
	enc, _ := att.Encode()
	msg, _ := attest.InjectTrailer("feat: implement feature", enc)
	commitFeature := commitWithMessage(t, dir, msg)

	// Volver a main y añadir otro archivo que hace que el árbol de main sea diferente
	runGit(t, dir, "checkout", "main")
	writeAndStage(t, dir, "extra.txt", "extra main content\n")
	commitWithMessage(t, dir, "feat: extra main commit")

	// Cherry-pick del commit firmado de feature hacia main
	runGit(t, dir, "cherry-pick", commitFeature)
	cherryHead := runGit(t, dir, "rev-parse", "HEAD")
	cherryTree := runGit(t, dir, "rev-parse", "HEAD^{tree}")

	// El cherry-pick heredó el mensaje y el trailer, pero su árbol real es cherryTree != treeFeature
	msgCherry := commitMessage(t, dir, cherryHead)
	rawTrailer, err := attest.ExtractTrailer(msgCherry)
	if err != nil {
		t.Fatalf("ExtractTrailer: %v", err)
	}
	attCherry, _ := attest.Decode(rawTrailer)

	opts := attest.VerifyOptions{
		ExpectedTreeSHA:    cherryTree,
		ExpectedPolicyHash: strongPolicyHash,
		MaxAge:             testMaxAge,
	}

	err = verifier.Verify(attCherry, opts)
	if !errors.Is(err, attest.ErrTreeMismatch) {
		t.Fatalf("Cherry-pick en rama con árbol distinto debía fallar con ErrTreeMismatch, got: %v", err)
	}
}

// ============================================================================
// ESCENARIO 13: HOSTIL — NORMALIZACIÓN DE SALTOS DE LÍNEA CRLF DE WINDOWS
// ============================================================================
func TestE2E_Hostil_CRLF_Normalizacion(t *testing.T) {
	signer, _ := attest.GenerateSigner()
	verifier := attest.NewEd25519Verifier(signer.PublicKey())

	claims := attest.Claims{
		Version:    attest.Version,
		TreeSHA:    "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		PolicyHash: strongPolicyHash,
		Timestamp:  time.Now().UTC().Unix(),
	}
	att, _ := signer.Sign(claims)
	enc, _ := att.Encode()

	// Mensaje con CRLF explícito (\r\n) estilo editor Windows
	msgCRLF := fmt.Sprintf("feat: commit desde windows\r\n\r\nDescripcion detallada.\r\n\r\nCodeGuard-Attestation: %s\r\n", enc)

	extracted, err := attest.ExtractTrailer(msgCRLF)
	if err != nil {
		t.Fatalf("ExtractTrailer falló con CRLF: %v", err)
	}

	attDecoded, err := attest.Decode(extracted)
	if err != nil {
		t.Fatalf("Decode falló: %v", err)
	}

	opts := attest.VerifyOptions{
		ExpectedTreeSHA:    claims.TreeSHA,
		ExpectedPolicyHash: strongPolicyHash,
		MaxAge:             testMaxAge,
	}

	if err := verifier.Verify(attDecoded, opts); err != nil {
		t.Fatalf("Verificación falló con mensaje CRLF: %v", err)
	}
}

// ============================================================================
// ESCENARIO 14: FULL PROVENANCE — BINDING DE PADRES (ParentSHAs Mismatch)
// ============================================================================
func TestE2E_FullProvenance_ParentMismatch(t *testing.T) {
	dir := initRepo(t)
	signer, _ := attest.GenerateSigner()
	verifier := attest.NewEd25519Verifier(signer.PublicKey())

	// Commit 1 en main
	writeAndStage(t, dir, "app.txt", "content")
	p1 := commitWithMessage(t, dir, "feat: commit 1")

	// Commit 2 firmado con p1 como padre
	writeAndStage(t, dir, "app2.txt", "content2")
	tree2 := treeSHA(t, dir)

	claims := attest.Claims{
		Version:     attest.Version,
		TreeSHA:     tree2,
		ParentSHAs:  []string{p1},
		PolicyHash:  strongPolicyHash,
		AuthorEmail: "dev@empresa-ejemplo.com",
		Timestamp:   time.Now().UTC().Unix(),
	}
	att, _ := signer.Sign(claims)
	enc, _ := att.Encode()

	msg, _ := attest.InjectTrailer("feat: commit 2", enc)
	head2 := commitWithMessage(t, dir, msg)

	msgLeido := commitMessage(t, dir, head2)
	rawTrailer, _ := attest.ExtractTrailer(msgLeido)
	attDecoded, _ := attest.Decode(rawTrailer)

	// Simular verificación en una rama alternativa con otro padre p2 falso
	falsoPadre := "0000000000000000000000000000000000000000"
	opts := attest.VerifyOptions{
		ExpectedTreeSHA:    tree2,
		ExpectedParentSHAs: []string{falsoPadre},
		ExpectedPolicyHash: strongPolicyHash,
		MaxAge:             testMaxAge,
	}

	err := verifier.Verify(attDecoded, opts)
	if !errors.Is(err, attest.ErrParentMismatch) {
		t.Fatalf("Verificación con padre falso debía fallar con ErrParentMismatch, got: %v", err)
	}
}

// ============================================================================
// ESCENARIO 15: FULL PROVENANCE — BINDING DE IDENTIDAD DE AUTOR (Author Mismatch)
// ============================================================================
func TestE2E_FullProvenance_AuthorMismatch(t *testing.T) {
	signer, _ := attest.GenerateSigner()
	verifier := attest.NewEd25519Verifier(signer.PublicKey())

	claims := attest.Claims{
		Version:     attest.Version,
		TreeSHA:     "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		ParentSHAs:  []string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4"},
		AuthorEmail: "atacante@externo.com",
		PolicyHash:  strongPolicyHash,
		Timestamp:   time.Now().UTC().Unix(),
	}
	att, _ := signer.Sign(claims)

	opts := attest.VerifyOptions{
		ExpectedTreeSHA:    claims.TreeSHA,
		ExpectedParentSHAs: claims.ParentSHAs,
		ExpectedAuthor:     "director@empresa.com", // El servidor espera la firma del director
		ExpectedPolicyHash: strongPolicyHash,
		MaxAge:             testMaxAge,
	}

	err := verifier.Verify(att, opts)
	if !errors.Is(err, attest.ErrAuthorMismatch) {
		t.Fatalf("Intento de suplantación de autor debía fallar con ErrAuthorMismatch, got: %v", err)
	}
}
