package shadow

import (
	"path"
	"strings"

	"github.com/gobwas/glob"

	"codeguard/internal/config"
	"codeguard/internal/ipc"
)

// ── Etapa 3: clasificación de riesgo (heurística, sin ML en v1) ──────────

func matchAny(patterns []string, p string) bool {
	for _, pat := range patterns {
		if g, err := glob.Compile(pat, '/'); err == nil && g.Match(p) {
			return true
		}
	}
	return false
}

var manifests = map[string]bool{
	"package.json": true, "package-lock.json": true, "go.mod": true, "go.sum": true,
	"requirements.txt": true, "pom.xml": true, "pubspec.yaml": true, "pubspec.lock": true,
}

var securityConfigs = map[string]bool{
	"androidmanifest.xml": true, "web.config": true, "appsettings.json": true,
	"dockerfile": true, "docker-compose.yml": true,
}

func RiskScore(cfg *config.Config, req *ipc.Request) int {
	w := cfg.Risk.Weights
	score := 0
	var anyMigration, anySensitive, anyDep, anyQuery, anySecCfg bool
	allTests, allDocs := true, true

	for _, f := range req.StagedFiles {
		p := strings.ToLower(f.Path)
		base := path.Base(p)
		if matchAny(cfg.Paths.Migrations, f.Path) {
			anyMigration = true
		}
		if matchAny(cfg.Paths.Sensitive, f.Path) {
			anySensitive = true
		}
		if manifests[base] || strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".lock") {
			anyDep = true
		}
		if strings.HasSuffix(p, ".sql") {
			anyQuery = true
		}
		if securityConfigs[base] || strings.HasSuffix(p, ".tf") {
			anySecCfg = true
		}
		isTest := strings.Contains(p, "test") || strings.Contains(p, "spec")
		isDoc := strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".txt")
		if !isTest {
			allTests = false
		}
		if !isDoc {
			allDocs = false
		}
	}
	add := func(key string, cond bool) {
		if cond {
			score += w[key]
		}
	}
	add("touches_migration", anyMigration)
	add("touches_sensitive", anySensitive)
	add("ai_generated", req.AIGenerated)
	add("touches_security_config", anySecCfg)
	add("adds_dependency", anyDep)
	add("touches_query", anyQuery)
	add("many_files", len(req.StagedFiles) > 10)
	add("tests_only", allTests && len(req.StagedFiles) > 0)
	add("docs_only", allDocs && len(req.StagedFiles) > 0)
	if score < 0 {
		return 0
	}
	return score
}

