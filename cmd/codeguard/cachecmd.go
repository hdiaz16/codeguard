package main

import (
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
