package main

import (
	"fmt"
	"os"
	"path/filepath"

	"codeguard/internal/config"
	"codeguard/internal/daemon"
	sgengine "codeguard/internal/engines/semgrep"
	"codeguard/internal/gitdiff"
	"codeguard/internal/store"
)

// abrirCache arma el caché de resultados por archivo (§9) para los comandos
// que analizan con la capa determinista: report, baseline y el hook cuando el
// daemon no responde. Si el store no abre, se analiza sin caché — es una
// aceleración, no un requisito. Cerrar() siempre es seguro de llamar.
func abrirCache(repoRoot string, cfg *config.Config) (cache sgengine.Cache, cerrar func()) {
	st, err := store.Open(store.DefaultPath())
	if err != nil {
		// Sin caché se analiza igual (P4), pero el motivo NO se traga: desde
		// que Migrate verifica checksums, este error puede estar diciendo «tu
		// esquema divergió y nada se escribirá encima» — y un usuario cuyo
		// caché e historial se apagaron en silencio no tiene ni la primera
		// pista de por qué.
		fmt.Fprintln(os.Stderr, "aviso: la BD local no abre (se analiza sin caché ni historial):", err)
		return nil, func() {}
	}
	remote := gitRemote(repoRoot)
	// RepoIDDe y no CanonicalRepoID a secas: sin el respaldo, un repo sin remote
	// cacheaba bajo la cadena vacía —o sea, en el mismo cajón que TODOS los
	// demás repos sin remote de la máquina—, y el caché por archivo se
	// compartiría entre proyectos distintos.
	cache = daemon.CachePorArchivo(st, store.RepoIDDe(repoRoot, remote), remote, filepath.Base(repoRoot), cfg)
	return cache, func() { _ = st.Close() }
}

// conHuellas completa el SHA de cada archivo — la clave del caché. Sin huella
// un archivo simplemente no es cacheable, así que el error de lectura ya está
// contemplado: SHA256De devuelve vacío.
func conHuellas(repoRoot string, files []gitdiff.ChangedFile) []gitdiff.ChangedFile {
	for i := range files {
		if files[i].SHA256 == "" && files[i].Status != "D" {
			files[i].SHA256 = gitdiff.SHA256De(repoRoot, files[i].Path)
		}
	}
	return files
}
