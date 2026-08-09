// Package registry lleva la lista de proyectos enrolados en esta máquina.
// Se alimenta de `codeguard init` y de cada análisis, para que el panel y el
// explorador muestren TODOS los proyectos — no solo los que ya commitearon.
package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Repo struct {
	Root     string `json:"root"`
	Nombre   string `json:"nombre"`
	Alta     string `json:"alta"`    // cuándo se enroló
	UltVez   string `json:"ult_vez"` // último análisis
	Lenguaje string `json:"lenguaje,omitempty"`
}

var mu sync.Mutex

func path() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "codeguard")
	os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "repos.json")
}

// Load devuelve los proyectos conocidos, ordenados por nombre.
func Load() []Repo {
	mu.Lock()
	defer mu.Unlock()
	raw, err := os.ReadFile(path())
	if err != nil {
		return nil
	}
	var repos []Repo
	if json.Unmarshal(raw, &repos) != nil {
		return nil
	}
	// los que ya no existen en disco se olvidan solos
	var alive []Repo
	for _, r := range repos {
		if _, err := os.Stat(r.Root); err == nil {
			alive = append(alive, r)
		}
	}
	sort.Slice(alive, func(i, j int) bool { return alive[i].Nombre < alive[j].Nombre })
	return alive
}

// Add registra (o actualiza) un proyecto. Idempotente.
func Add(root, nombre, lenguaje string) {
	root = filepath.ToSlash(root)
	mu.Lock()
	defer mu.Unlock()
	var repos []Repo
	if raw, err := os.ReadFile(path()); err == nil {
		json.Unmarshal(raw, &repos)
	}
	now := time.Now().Format(time.RFC3339)
	found := false
	for i := range repos {
		if repos[i].Root == root {
			repos[i].Nombre = nombre
			repos[i].UltVez = now
			if lenguaje != "" {
				repos[i].Lenguaje = lenguaje
			}
			found = true
			break
		}
	}
	if !found {
		repos = append(repos, Repo{Root: root, Nombre: nombre, Alta: now, UltVez: now, Lenguaje: lenguaje})
	}
	if data, err := json.MarshalIndent(repos, "", "  "); err == nil {
		os.WriteFile(path(), data, 0o644)
	}
}
