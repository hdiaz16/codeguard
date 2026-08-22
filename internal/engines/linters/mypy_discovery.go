package linters

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

func configMypyDe(repoRoot, rel string) (string, bool) {
	if enEntornoVirtual(rel) {
		return "", false
	}
	dir := path.Dir(rel)
	for {
		abs := filepath.Join(repoRoot, filepath.FromSlash(dir))
		if hayAlguno(abs, configsMypyPropias) {
			return dir, true
		}
		// setup.cfg y pyproject.toml son archivos COMPARTIDOS: existen en casi
		// todo repo de Python y no dicen nada por sí solos. Sólo cuentan si
		// alojan la sección de mypy, y eso exige mirar dentro.
		if tieneSeccion(filepath.Join(abs, "setup.cfg"), "mypy") {
			return dir, true
		}
		if tieneSeccion(filepath.Join(abs, "pyproject.toml"), "tool.mypy") {
			return dir, true
		}
		if dir == "." || dir == "/" {
			return "", false
		}
		dir = path.Dir(dir)
	}
}

// enEntornoVirtual reconoce las carpetas donde vive el intérprete y sus
// dependencias. Es el node_modules de Python: analizar ahí tarda minutos y no
// es código del repo. Normalmente están en .gitignore y no llegarían al diff,
// pero un repo que versione su venv por error no debe tumbar el pre-commit.
func enEntornoVirtual(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case ".venv", "venv", "site-packages", ".tox", ".mypy_cache", "__pycache__":
			return true
		}
	}
	return false
}

// tieneSeccion dice si un archivo INI o TOML declara alguna de las secciones
// dadas. Se parsea a mano —sólo las cabeceras— en vez de traer un lector de
// TOML: la pregunta es "¿existe esta sección?", no "¿qué dice?", y una
// dependencia nueva para eso no se paga.
//
// Acepta la forma de tabla anidada, para que un pyproject.toml que sólo traiga
// [[tool.mypy.overrides]] cuente igual: TOML crea la tabla padre y mypy toma el
// archivo como suyo. Lo que NO cuenta es [tool.mypyc] —mypyc es el compilador,
// otra herramienta— y de ahí que el prefijo se compare con el punto incluido.
//
// Un setup.cfg con sólo secciones [mypy-modulo] por módulo y sin [mypy] queda
// fuera: es la lectura literal de la documentación, y equivocarse hacia "no
// aplica" es el lado seguro de esta decisión.
func tieneSeccion(abs string, nombres ...string) bool {
	datos, err := os.ReadFile(abs)
	if err != nil {
		return false
	}
	for _, linea := range strings.Split(string(datos), "\n") {
		// TrimSpace se come también el \r de los repos en CRLF, que en Windows
		// son la mayoría.
		s := strings.TrimSpace(linea)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") || !strings.HasPrefix(s, "[") {
			continue
		}
		cierre := strings.IndexByte(s, ']')
		if cierre < 0 {
			continue
		}
		titulo := strings.TrimSpace(strings.Trim(s[:cierre+1], "[]"))
		for _, n := range nombres {
			if titulo == n || strings.HasPrefix(titulo, n+".") {
				return true
			}
		}
	}
	return false
}

// maxLineaComandosPy acota los argumentos de una invocación.
//
// El límite es el de semgrep (32767 de CreateProcess) y no el de eslint (8191
// de cmd.exe): pip instala mypy como mypy.exe, un ejecutable de verdad, no como
// el shim .cmd que reparte npm. Se verificó mirando el directorio de scripts
// del usuario. 30000 deja margen para la ruta del binario y las tres banderas.

