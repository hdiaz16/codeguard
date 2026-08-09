package codegraph

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed assets
var assets embed.FS

// RenderHTML devuelve la página del explorador con TODO embebido en un solo
// documento (librería + datos), lista para una ventana del daemon — sin
// navegador, sin archivos sueltos, sin red.
func RenderHTML(g *Graph) (string, error) {
	lib, err := assets.ReadFile("assets/3d-force-graph.js")
	if err != nil {
		return "", err
	}
	page, err := assets.ReadFile("assets/explorer.html")
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	html := strings.Replace(string(page), marker, string(data), 1)
	html = strings.Replace(html,
		`<script src="3d-force-graph.js"></script>`,
		"<script>"+string(lib)+"</script>", 1)
	return html, nil
}

const marker = `/*__GRAPH_DATA__*/ {"nodes":[],"edges":[],"lang":"go","root":""}`

// WriteExplorer escribe el explorador como carpeta autocontenida (modo CLI).
func WriteExplorer(g *Graph, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	// librerías tal cual (3d-force-graph trae ThreeJS + d3-force-3d dentro)
	for _, name := range []string{"3d-force-graph.js"} {
		raw, err := assets.ReadFile("assets/" + name)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(outDir, name), raw, 0o644); err != nil {
			return "", err
		}
	}
	// página con los datos inyectados
	page, err := assets.ReadFile("assets/explorer.html")
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	html := strings.Replace(string(page), marker, string(data), 1)
	if !strings.Contains(html, `"nodes"`) {
		return "", fmt.Errorf("no se pudo inyectar el grafo en la plantilla")
	}
	out := filepath.Join(outDir, "index.html")
	if err := os.WriteFile(out, []byte(html), 0o644); err != nil {
		return "", err
	}
	return out, nil
}
