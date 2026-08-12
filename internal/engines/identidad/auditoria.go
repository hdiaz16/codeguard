package identidad

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/engines/proc"
)

// Auditoría de nuestra propia cadena de suministro.
//
// Verificar() responde "¿este binario es el que publicó su autor?". Esto
// responde la otra mitad, que es igual de importante y no la cubría nadie:
// "¿y lo que publicó su autor tiene vulnerabilidades conocidas?". Un motor
// puede coincidir con su hash a la perfección y arrastrar un CVE crítico en
// una dependencia; el hash sólo prueba que nadie lo manipuló por el camino.
//
// La exigencia es del usuario y es la correcta para esta herramienta: no
// podemos pedirle a un equipo que no despliegue dependencias vulnerables
// mientras nosotros le instalamos nueve binarios sin mirarlos. Una herramienta
// de seguridad que no se audita a sí misma pide una confianza que no se ganó.
//
// Se apoya en trivy, que ya distribuimos: los binarios de Go llevan dentro su
// lista de módulos y trivy la lee, y para los paquetes de Python lee el
// directorio de site-packages.

// Riesgo es lo que se encontró en un artefacto nuestro.
type Riesgo struct {
	Artefacto string // el motor o el paquete
	CVE       string
	Severidad string
	Paquete   string
	Version   string
	Corregida string // versión donde está resuelto; vacío si no hay
}

// Auditoria es el resultado completo de mirar todo lo que distribuimos.
type Auditoria struct {
	Escaneados []string // artefactos que sí se pudieron mirar
	Omitidos   []string // y los que no, con su motivo — nunca en silencio
	Riesgos    []Riesgo
}

// Graves son los que no deberían viajar en un instalador: crítico y alto.
func (a Auditoria) Graves() []Riesgo {
	var out []Riesgo
	for _, r := range a.Riesgos {
		if r.Severidad == "CRITICAL" || r.Severidad == "HIGH" {
			out = append(out, r)
		}
	}
	return out
}

type salidaTrivy struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// Auditar escanea con trivy los motores descargables y los paquetes de Python.
//
// dirMotores es donde viven los binarios; dirPython puede ir vacío si no se
// sabe dónde instaló pip (entonces se omite y se dice, en vez de dar por
// limpio lo que no se miró — ese silencio es justo el fallo que este proyecto
// lleva un mes persiguiendo).
func Auditar(ctx context.Context, dirMotores, dirPython, binTrivy string) (Auditoria, error) {
	var a Auditoria
	if binTrivy == "" {
		binTrivy = filepath.Join(dirMotores, "trivy.exe")
	}
	if _, err := os.Stat(binTrivy); err != nil {
		return a, fmt.Errorf("sin trivy no hay auditoría posible: %w", err)
	}

	objetivos := map[string]string{} // nombre → ruta
	for nombre := range cargado.Motores {
		ruta := filepath.Join(dirMotores, nombre+".exe")
		if _, err := os.Stat(ruta); err == nil {
			objetivos[nombre] = ruta
		} else {
			a.Omitidos = append(a.Omitidos, nombre+" (no instalado)")
		}
	}
	// Los motores de Go que compila el toolchain del usuario también viajan en
	// el instalador, aunque no estén en el manifiesto de hashes.
	for _, nombre := range []string{"govulncheck", "staticcheck"} {
		if _, ya := objetivos[nombre]; ya {
			continue
		}
		ruta := filepath.Join(dirMotores, nombre+".exe")
		if _, err := os.Stat(ruta); err == nil {
			objetivos[nombre] = ruta
		} else {
			a.Omitidos = append(a.Omitidos, nombre+" (no instalado)")
		}
	}
	if dirPython != "" {
		if _, err := os.Stat(dirPython); err == nil {
			objetivos["motores de Python"] = dirPython
		} else {
			a.Omitidos = append(a.Omitidos, "motores de Python (no encuentro site-packages)")
		}
	} else {
		a.Omitidos = append(a.Omitidos, "motores de Python (no sé dónde instaló pip)")
	}

	nombres := make([]string, 0, len(objetivos))
	for n := range objetivos {
		nombres = append(nombres, n)
	}
	sort.Strings(nombres)

	for _, nombre := range nombres {
		riesgos, err := escanear(ctx, binTrivy, objetivos[nombre], nombre)
		if err != nil {
			a.Omitidos = append(a.Omitidos, nombre+" ("+err.Error()+")")
			continue
		}
		a.Escaneados = append(a.Escaneados, nombre)
		a.Riesgos = append(a.Riesgos, riesgos...)
	}
	return a, nil
}

func escanear(ctx context.Context, binTrivy, objetivo, nombre string) ([]Riesgo, error) {
	cmd := exec.CommandContext(ctx, binTrivy,
		"fs", "--scanners", "vuln", "--format", "json", "--quiet", "--skip-db-update", objetivo)
	cmd.Env = proc.Entorno()
	salida, err := proc.Correr(ctx, cmd, proc.MaxSalida)
	if err != nil && len(salida.Stdout) == 0 {
		return nil, fmt.Errorf("trivy no pudo mirarlo: %w", err)
	}
	var res salidaTrivy
	if err := json.Unmarshal(salida.Stdout, &res); err != nil {
		return nil, fmt.Errorf("salida de trivy ilegible")
	}
	var out []Riesgo
	for _, r := range res.Results {
		for _, v := range r.Vulnerabilities {
			out = append(out, Riesgo{
				Artefacto: nombre,
				CVE:       v.VulnerabilityID,
				Severidad: strings.ToUpper(v.Severity),
				Paquete:   v.PkgName,
				Version:   v.InstalledVersion,
				Corregida: v.FixedVersion,
			})
		}
	}
	return out, nil
}
