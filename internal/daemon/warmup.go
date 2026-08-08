package daemon

import (
	"bufio"
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Precalentamiento (spike S5 / corrección H3): el primer commit del día no
// debe pagar el tsc frío. El daemon recuerda qué repos atiende y recalienta
// sus compiladores incrementales al arrancar, en background.

func warmListPath() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "codeguard", "warm-repos.txt")
}

var warmMu sync.Mutex

// RememberRepo apunta el repo para precalentarlo en el próximo arranque.
func RememberRepo(repoRoot string) {
	warmMu.Lock()
	defer warmMu.Unlock()
	path := warmListPath()
	existing := map[string]bool{}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			existing[strings.TrimSpace(sc.Text())] = true
		}
		f.Close()
	}
	if existing[repoRoot] {
		return
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(repoRoot + "\n")
}

// WarmAll recalienta tsc en cada repo recordado. Llamar en goroutine al
// arrancar el daemon; nunca está en el camino de ningún commit.
func WarmAll(ctx context.Context) {
	f, err := os.Open(warmListPath())
	if err != nil {
		return
	}
	var repos []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if r := strings.TrimSpace(sc.Text()); r != "" {
			repos = append(repos, r)
		}
	}
	f.Close()

	for _, repo := range repos {
		if ctx.Err() != nil {
			return
		}
		if _, err := os.Stat(filepath.Join(repo, "tsconfig.json")); err != nil {
			continue
		}
		start := time.Now()
		wctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		bin := "npx.cmd"
		args := []string{"--no-install", "tsc", "--noEmit", "--incremental", "--pretty", "false"}
		if local := filepath.Join(repo, "node_modules", ".bin", "tsc.cmd"); fileExists(local) {
			bin, args = local, []string{"--noEmit", "--incremental", "--pretty", "false"}
		}
		cmd := exec.CommandContext(wctx, bin, args...)
		cmd.Dir = repo
		cmd.Run() // el exit code no importa: solo queremos el caché caliente
		cancel()
		log.Printf("precalentado tsc en %s (%.1f s)", filepath.Base(repo), time.Since(start).Seconds())
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
