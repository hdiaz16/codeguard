// codeguard-release es la herramienta de la MÁQUINA DE RELEASE (jamás se
// distribuye): genera la clave de firma y firma los manifiestos de rulepack.
// Decisión de Héctor (2026-08-23, docs/threat-model-rulepack.md): la clave
// privada vive local, cifrada con DPAPI y con respaldo offline — el release
// es local y la clave no toca ni el repo ni la nube.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/dpapi"
	"codeguard/internal/fsutil"
	"codeguard/internal/manifest"
	"codeguard/internal/rulepack"
)

func main() {
	raiz := &cobra.Command{
		Use:           "codeguard-release",
		Short:         "Herramienta de release: clave de firma y manifiestos de rulepack",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	raiz.AddCommand(keygenCmd(), signRulepackCmd())
	if err := raiz.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "codeguard-release:", err)
		os.Exit(1)
	}
}

// dirClaves es donde vive la privada DPAPI-cifrada: fuera del repo, en el
// perfil del usuario de release.
func dirClaves() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("sin directorio de usuario: %w", err)
	}
	return filepath.Join(home, ".codeguard-release"), nil
}

// idDeClave deriva el id del contenido de la pública: autoautenticado — un
// id no puede apuntar a otra clave sin que la verificación lo delate.
func idDeClave(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "rel-" + hex.EncodeToString(sum[:4])
}

func keygenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen",
		Short: "Genera el par de claves de release (privada DPAPI-cifrada + respaldo offline)",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := dirClaves()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			id := idDeClave(pub)
			rutaPriv := filepath.Join(dir, id+".key.dpapi")
			if _, err := os.Stat(rutaPriv); err == nil {
				return fmt.Errorf("ya existe %s — una clave no se pisa; si de verdad quieres otra, muévela primero a mano", rutaPriv)
			}
			protegida, err := dpapi.Proteger(priv.Seed(), []byte("codeguard-release-key-v1"))
			if err != nil {
				return err
			}
			if err := fsutil.EscribirAtomico(rutaPriv, protegida, 0o600); err != nil {
				return err
			}
			if err := fsutil.EscribirAtomico(filepath.Join(dir, id+".pub"),
				[]byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
				return err
			}

			fmt.Printf("clave de release generada: %s\n", id)
			fmt.Printf("privada (DPAPI, solo esta cuenta y esta máquina): %s\n\n", rutaPriv)
			fmt.Println("RESPALDO OFFLINE — copia esta línea a un USB o papel y guárdala fuera de la máquina.")
			fmt.Println("Se muestra UNA sola vez; con ella se reconstruye la clave si la máquina muere:")
			fmt.Printf("\n  %s.seed = %s\n\n", id, base64.StdEncoding.EncodeToString(priv.Seed()))
			fmt.Println("Para EMBEBER la pública en el binario, pega esta línea en internal/manifest/claves.go:")
			fmt.Printf("\n  %q: clave(%q),\n\n", id, hex.EncodeToString(pub))
			fmt.Println("y recompila: desde ese binario, los rulepacks instalados EXIGEN manifiesto firmado.")
			return nil
		},
	}
}

func signRulepackCmd() *cobra.Command {
	var claveID string
	cmd := &cobra.Command{
		Use:   "sign-rulepack <dir-del-rulepack>",
		Short: "Construye y firma manifest.json/.sig del árbol de un rulepack",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dirPack, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			version := filepath.Base(dirPack)

			priv, id, err := cargarPrivada(claveID)
			if err != nil {
				return err
			}

			// Si un manifiesto viejo quedó dentro, el inventario lo excluye
			// (autorreferencia) — firmar un árbol que ya trae manifest es
			// legítimo al re-firmar.
			inventario, err := rulepack.Inventario(dirPack)
			if err != nil {
				return fmt.Errorf("el árbol no es firmable: %w", err)
			}
			files := make([]manifest.ArchivoDeRulepack, len(inventario))
			for i, a := range inventario {
				files[i] = manifest.ArchivoDeRulepack{Path: a.Rel, SHA256: a.SHA256, SizeBytes: a.Size}
			}
			m := &manifest.RulepackManifest{
				Schema:      manifest.RulepackSchemaSoportado,
				Rulepack:    version,
				GeneratedAt: time.Now().UTC().Format(time.RFC3339),
				SignerKeyID: id,
				TreeDigest:  rulepack.DigestDeInventario(inventario),
				Files:       files,
			}
			manifestJSON, firma, err := manifest.FirmarRulepack(m, priv)
			if err != nil {
				return err
			}
			if err := fsutil.EscribirAtomico(filepath.Join(dirPack, "manifest.json"), manifestJSON, 0o644); err != nil {
				return err
			}
			if err := fsutil.EscribirAtomico(filepath.Join(dirPack, "manifest.sig"), firma, 0o644); err != nil {
				return err
			}

			// El LISTO se gana: se re-lee del disco y se verifica con la
			// pública antes de afirmar nada.
			leidoJSON, err := os.ReadFile(filepath.Join(dirPack, "manifest.json"))
			if err != nil {
				return err
			}
			leidaFirma, err := os.ReadFile(filepath.Join(dirPack, "manifest.sig"))
			if err != nil {
				return err
			}
			verificado, err := manifest.CargarYVerificarRulepack(leidoJSON, leidaFirma,
				map[string]ed25519.PublicKey{id: priv.Public().(ed25519.PublicKey)})
			if err != nil {
				return fmt.Errorf("lo escrito NO verifica (no se afirma nada): %w", err)
			}
			fmt.Printf("rulepack %s firmado: %d archivos, digest %.12s…, clave %s\n",
				verificado.Rulepack, len(verificado.Files), verificado.TreeDigest, id)
			return nil
		},
	}
	cmd.Flags().StringVar(&claveID, "clave", "", "id de la clave a usar (con una sola instalada, se resuelve sola)")
	return cmd
}

// cargarPrivada localiza la clave DPAPI del perfil (o la pedida por id) y la
// desprotege. Con varias instaladas y sin --clave, se rehúsa a adivinar.
func cargarPrivada(claveID string) (ed25519.PrivateKey, string, error) {
	dir, err := dirClaves()
	if err != nil {
		return nil, "", err
	}
	patron := "*.key.dpapi"
	if claveID != "" {
		patron = claveID + ".key.dpapi"
	}
	rutas, err := filepath.Glob(filepath.Join(dir, patron))
	if err != nil {
		return nil, "", err
	}
	switch len(rutas) {
	case 0:
		return nil, "", fmt.Errorf("no hay clave de release en %s — corre `codeguard-release keygen` primero", dir)
	case 1:
	default:
		return nil, "", fmt.Errorf("hay %d claves en %s: elige con --clave <id>", len(rutas), dir)
	}
	protegida, err := os.ReadFile(rutas[0])
	if err != nil {
		return nil, "", err
	}
	seed, err := dpapi.Desproteger(protegida, []byte("codeguard-release-key-v1"))
	if err != nil {
		return nil, "", fmt.Errorf("no se pudo desproteger la clave (¿otra cuenta o máquina?): %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, "", fmt.Errorf("la clave desprotegida mide %d bytes, se esperan %d — archivo corrupto", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	id := idDeClave(priv.Public().(ed25519.PublicKey))
	return priv, id, nil
}
