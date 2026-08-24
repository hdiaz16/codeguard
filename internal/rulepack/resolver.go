package rulepack

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"codeguard/internal/manifest"
)

// Resolver es EL punto único de resolución del rulepack pinneado (t.103: las
// resoluciones dispersas — RulepackDir del daemon, la re-resolución de
// RulepackEsDelRepo y la copia inlineada del comando ci, que además tenía el
// orden INVERTIDO — murieron aquí). Todos los consumidores reciben esta
// identidad ya resuelta; nadie vuelve a buscar por ruta.
//
// El orden de candidatos es una decisión de SEGURIDAD medida, no de
// conveniencia: instalado (junto al binario, un nivel arriba, instalación
// estándar) ANTES que el vendoreado en el repo. Con el repo primero, el repo
// ANALIZADO decidía qué reglas se le aplicaban: bastaba traer un
// `rulepacks/<la version que pinnea>/` con reglas de relleno para que las de
// la casa no llegaran a mirar el código. Medido: el mismo archivo con una
// inyección SQL de manual salía BLOQUEADO con el rulepack instalado y
// «commit permitido» con el del repo. Sin carrera y sin atacante sofisticado:
// basta clonar el repositorio.
//
// El vendoreado sigue existiendo como RESPALDO porque resuelve un fallo real
// (un binario que no es el instalado no tiene rulepacks al lado, y sin esto
// cada repo perdería las reglas de la casa EN SILENCIO). Si están los dos, el
// mismo número nombrando dos artefactos distintos es una colisión, y en una
// colisión gana el de la organización: la versión es una promesa de paridad
// con el CI. Un equipo que de verdad necesite reglas propias las publica con
// SU número de versión.
//
// Devuelve la identidad con su digest calculado (re-hash completo, sin caché
// por mtime — veto de GPT t.103). Errores:
//   - ErrNoEncontrado: ningún candidato existe; la identidad devuelta apunta
//     al sitio del repo donde el dev PODRÍA vendorearlo (para que el mensaje
//     hable de un lugar concreto) y Digest va vacío.
//   - árbol presente pero inválido/ilegible (symlink dentro, colisión de
//     mayúsculas, sin archivos): se devuelve la identidad SIN digest y el
//     error con nombre. El candidato elegido no cambia — un instalado roto
//     JAMÁS cae en silencio al vendoreado (t.103); hoy el análisis sigue y
//     estampa digest vacío (observabilidad primero), la tanda (c) lo vuelve
//     rechazo cuando la verificación de firma exista.
func Resolver(repoRoot, version string) (Identity, error) {
	return ResolverConClaves(repoRoot, version, manifest.ClavesDeRelease())
}

// ResolverConClaves es Resolver con el registro de claves inyectable (los
// tests firman con las suyas; producción usa las embebidas del binario).
//
// Política por origen (síntesis t.104):
//   - INSTALADO con claves embebidas: exige manifest.json/.sig firmados, con
//     la versión DENTRO de lo firmado igual al nombre del directorio (mata el
//     misbinding) y el digest del árbol coincidente. Cualquier falla = error
//     con nombre — y JAMÁS se cae al vendoreado.
//   - INSTALADO sin claves embebidas (binario de desarrollo o anterior al
//     primer release firmado): Verified=false, sin error — exigir firma sin
//     tener con qué verificarla bloquearía al mundo entero; la exigencia se
//     enciende sola en el primer binario con clave.
//   - VENDOREADO: sin firma exigida (son las reglas del propio equipo), se
//     dice por Source y el digest se estampa igual.
func ResolverConClaves(repoRoot, version string, claves map[string]ed25519.PublicKey) (Identity, error) {
	type candidato struct {
		dir string
		src Source
	}
	var candidatos []candidato
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidatos = append(candidatos,
			candidato{filepath.Join(dir, "rulepacks", version), SourceInstalled},
			candidato{filepath.Join(filepath.Dir(dir), "rulepacks", version), SourceInstalled})
	}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		candidatos = append(candidatos, candidato{filepath.Join(base, "CodeGuard", "rulepacks", version), SourceInstalled})
	}
	local := filepath.Join(repoRoot, "rulepacks", version)
	candidatos = append(candidatos, candidato{local, SourceVendored})

	for _, c := range candidatos {
		if _, err := os.Stat(c.dir); err != nil {
			continue
		}
		id := Identity{Path: c.dir, Version: version, Source: c.src}
		digest, err := DigestArbol(c.dir)
		if err != nil {
			return id, fmt.Errorf("rulepack %s en %s presente pero inválido: %w", version, c.dir, err)
		}
		id.Digest = digest
		if c.src == SourceInstalled && len(claves) > 0 {
			if err := verificarManifiesto(c.dir, version, digest, claves); err != nil {
				return id, fmt.Errorf("rulepack instalado %s NO verifica: %w", version, err)
			}
			id.Verified = true
		}
		return id, nil
	}
	return Identity{Path: local, Version: version, Source: SourceVendored},
		fmt.Errorf("%w: %s", ErrNoEncontrado, version)
}

// verificarManifiesto exige el manifiesto firmado de un rulepack instalado:
// firma válida contra el registro, versión firmada == nombre del directorio,
// y digest del árbol coincidente (con diagnóstico por archivo cuando no).
func verificarManifiesto(dir, version, digestArbol string, claves map[string]ed25519.PublicKey) error {
	manifestJSON, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("sin manifest.json (%v) — este binario exige rulepacks instalados firmados; reinstala uno firmado o vendorea reglas propias en el repo", err)
	}
	firma, err := os.ReadFile(filepath.Join(dir, "manifest.sig"))
	if err != nil {
		return fmt.Errorf("sin manifest.sig (%v)", err)
	}
	m, err := manifest.CargarYVerificarRulepack(manifestJSON, firma, claves)
	if err != nil {
		return err
	}
	if m.Rulepack != version {
		return fmt.Errorf("el manifiesto firmado dice %q y el directorio se llama %q — un rulepack presentándose como otro (misbinding)", m.Rulepack, version)
	}
	if m.TreeDigest != digestArbol {
		return fmt.Errorf("el árbol no es el firmado: digest %.12s… contra %.12s… del manifiesto — %s",
			digestArbol, m.TreeDigest, diagnosticoPorArchivo(dir, m))
	}
	return nil
}

// diagnosticoPorArchivo nombra QUÉ difiere entre el árbol y el manifiesto —
// para eso viaja Files: un digest que no cuadra sin decir dónde es un
// callejón.
func diagnosticoPorArchivo(dir string, m *manifest.RulepackManifest) string {
	inv, err := Inventario(dir)
	if err != nil {
		return "y el árbol ni siquiera se puede inventariar: " + err.Error()
	}
	enDisco := make(map[string]ArchivoDelArbol, len(inv))
	for _, a := range inv {
		enDisco[a.Rel] = a
	}
	firmados := make(map[string]bool, len(m.Files))
	for _, f := range m.Files {
		firmados[f.Path] = true
		d, ok := enDisco[f.Path]
		if !ok {
			return "falta el archivo firmado " + f.Path
		}
		if d.SHA256 != f.SHA256 || d.Size != f.SizeBytes {
			return "el archivo " + f.Path + " no es el firmado"
		}
	}
	for rel := range enDisco {
		if !firmados[rel] {
			return "el archivo " + rel + " no está en el manifiesto (añadido después de firmar)"
		}
	}
	return "difieren en algo que el inventario no distingue (¿orden o formato?)"
}

// RulepacksInstalados lista las versiones disponibles junto al binario y
// vendoreadas en el repo, ordenadas de más nueva a más vieja. Los nombres son
// fechas (2026.08.2), así que el orden lexicográfico inverso basta salvo por
// el número final: se compara por partes para que .10 no quede antes que .9.
// Mira los MISMOS sitios que Resolver, para que "instaladas: ..." no
// contradiga a la resolución.
func RulepacksInstalados(repoRoot string) []string {
	vistos := map[string]bool{}
	var out []string
	dirs := []string{filepath.Join(repoRoot, "rulepacks")}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		dirs = append(dirs, filepath.Join(dir, "rulepacks"), filepath.Join(filepath.Dir(dir), "rulepacks"))
	}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		dirs = append(dirs, filepath.Join(base, "CodeGuard", "rulepacks"))
	}
	for _, d := range dirs {
		entradas, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entradas {
			if e.IsDir() && !vistos[e.Name()] {
				vistos[e.Name()] = true
				out = append(out, e.Name())
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return masNuevo(out[i], out[j]) })
	return out
}

func masNuevo(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		if ea == nil && eb == nil {
			if na != nb {
				return na > nb
			}
			continue
		}
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return len(pa) > len(pb)
}
