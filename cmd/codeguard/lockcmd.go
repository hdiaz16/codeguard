package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/gitdiff"
	"codeguard/internal/lock"
	"codeguard/internal/rulepack"
	"codeguard/internal/shadow"
)

// codeguard lock ([W6 Q4]): la foto de coherencia entre entornos.
//   - `codeguard lock --update` la (re)genera y la escribe: es lo que se
//     commitea tras cambiar de versión de codeguard, de rulepack, de baseline,
//     de config o de fórmula de riesgo.
//   - `codeguard lock` (sin bandera) la VALIDA: compara lo que este entorno
//     calcularía contra lo fijado en el repo, y sale distinto de cero si hay
//     skew. El CI lo usa para rechazar; el gancho, para declarar sin bloquear.
func lockCmd() *cobra.Command {
	var update bool
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Genera o valida .codeguard.lock (la prueba de que local y CI analizarían igual)",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return err
			}
			cfg, err := config.Load(repoRoot)
			if err != nil {
				return err
			}
			if cfg == nil {
				return fmt.Errorf("el repo no está enrolado: falta %s", config.RelPath)
			}
			actual, err := lockActual(repoRoot, cfg)
			if err != nil {
				return err
			}
			if update {
				if err := lock.Escribir(repoRoot, actual); err != nil {
					return err
				}
				fmt.Printf("%s actualizado\n", lock.RelPath)
				return nil
			}
			// Validación.
			difs, hayLock, err := validarLock(repoRoot, cfg)
			if err != nil {
				return err
			}
			if !hayLock {
				fmt.Printf("no hay %s todavía — genera uno con `codeguard lock --update` y commitéalo\n", lock.RelPath)
				return nil
			}
			if len(difs) == 0 {
				fmt.Println("lock coherente: este entorno analizaría como el repo fijó")
				return nil
			}
			fmt.Printf("skew de coherencia (%s no corresponde a este entorno):\n", lock.RelPath)
			for _, d := range difs {
				fmt.Println("   -", d)
			}
			fmt.Println("corre `codeguard lock --update` y commitéalo si el cambio es intencional")
			return errSkew
		},
	}
	cmd.Flags().BoolVar(&update, "update", false, "(re)genera y escribe el lock en vez de validarlo")
	return cmd
}

// errSkew es el error centinela del skew de lock: el comando sale distinto de
// cero sin un stack de más — el CI mira el código de salida, no el texto.
var errSkew = errors.New("lock: skew de coherencia entre este entorno y el repo")

// lockActual calcula la foto de coherencia de ESTE entorno: el binario, el
// rulepack (nombre y digest del árbol), la config, la baseline y la fórmula de
// riesgo. Ninguna ruta ni dato de máquina — el lock se versiona.
func lockActual(repoRoot string, cfg *config.Config) (lock.Lock, error) {
	l := lock.Lock{
		Schema:             lock.Schema,
		CodeguardVersion:   version,
		RulepackVersion:    cfg.Rulepack,
		ConfigDigest:       cfg.Hash,
		RiskFormulaVersion: shadow.RiskFormulaVersion,
		RiskConfigHash:     shadow.RiskConfigHash(cfg),
	}
	// Digest del árbol del rulepack: el nombre puede mentir, el digest no. Un
	// rulepack ausente deja el digest vacío (no es error de este comando: el
	// análisis ya lo denuncia como capa degradada) salvo que sea un error real
	// de lectura.
	id, err := rulepack.Resolver(repoRoot, cfg.Rulepack)
	if err != nil && !errors.Is(err, rulepack.ErrNoEncontrado) {
		return lock.Lock{}, fmt.Errorf("resolviendo el rulepack para el lock: %w", err)
	}
	l.RulepackDigest = id.Digest

	// Digest de la baseline: su contenido exacto (los fingerprints suprimidos).
	// Ausente ⇒ vacío: un repo sin deuda aceptada no es un repo incoherente.
	d, err := digestArchivo(filepath.Join(repoRoot, filepath.FromSlash(baseline.RelPath)))
	if err != nil {
		return lock.Lock{}, err
	}
	l.BaselineDigest = d
	return l, nil
}

// validarLock compara el lock del repo contra lo que este entorno calcularía.
// Devuelve las diferencias (vacío = coherente), si HABÍA lock, y error solo si
// algo no se pudo leer. Lo usan el comando, el gancho y el CI: un único criterio.
func validarLock(repoRoot string, cfg *config.Config) ([]string, bool, error) {
	esperado, hayLock, err := lock.Cargar(repoRoot)
	if err != nil {
		return nil, false, err
	}
	if !hayLock {
		return nil, false, nil
	}
	actual, err := lockActual(repoRoot, cfg)
	if err != nil {
		return nil, true, err
	}
	return lock.Diferencias(esperado, actual), true, nil
}

// rechazarSkewDeLock es la validación del CI: un skew ANTES de analizar es un
// análisis sin paridad con lo que el repo fijó, así que se RECHAZA (error → exit
// ≠ 0, que es lo que el CI mira). Sin lock, o coherente, no dice nada y deja
// seguir.
func rechazarSkewDeLock(repoRoot string, cfg *config.Config) error {
	difs, hayLock, err := validarLock(repoRoot, cfg)
	if err != nil {
		return err
	}
	if !hayLock || len(difs) == 0 {
		return nil
	}
	fmt.Fprintf(os.Stderr, "%s: este entorno no corresponde a lo que el repo fijó — el análisis no tendría paridad:\n", lock.RelPath)
	for _, d := range difs {
		fmt.Fprintln(os.Stderr, "   -", d)
	}
	fmt.Fprintln(os.Stderr, "alinea el entorno o, si el cambio es intencional, corre `codeguard lock --update` y commitéalo")
	return errSkew
}

// declararSkewDeLock es la validación del gancho local: DECLARA el skew sin
// bloquear (bloquear al dev por una foto de coherencia le enseñaría el reflejo
// --no-verify). Best-effort: si el lock no se puede leer, no se dice nada y el
// commit sigue — el CI es quien tiene la última palabra sobre la paridad.
func declararSkewDeLock(repoRoot string, cfg *config.Config) {
	difs, hayLock, err := validarLock(repoRoot, cfg)
	if err != nil || !hayLock || len(difs) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "aviso: %s no corresponde a este entorno (el CI lo rechazaría):\n", lock.RelPath)
	for _, d := range difs {
		fmt.Fprintln(os.Stderr, "   -", d)
	}
	fmt.Fprintln(os.Stderr, "corre `codeguard lock --update` y commitéalo si el cambio es intencional")
}

// digestArchivo devuelve el sha256 hex del contenido, "" si el archivo no
// existe (no es error: la ausencia es un estado válido), error si no se pudo
// leer por otra causa.
func digestArchivo(ruta string) (string, error) {
	raw, err := os.ReadFile(ruta)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("digest de %s: %w", filepath.Base(ruta), err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
