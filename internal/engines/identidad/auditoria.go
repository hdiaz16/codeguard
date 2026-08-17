package identidad

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
	// Aceptados son riesgos graves que alguien firmó, con la firma delante.
	// No se descuentan del total: se enseñan aparte.
	Aceptados []Aceptado
	// AvisosExcepciones son las excepciones que no sirven: caducadas, sin firma,
	// o que ya no cubren nada. Se dicen aunque no cambien el veredicto.
	AvisosExcepciones []string
}

// Graves son los que no deberían viajar en un instalador: crítico y alto,
// descontando los que están aceptados por escrito y en vigor.
func (a Auditoria) Graves() []Riesgo {
	var out []Riesgo
	for _, r := range a.Riesgos {
		if r.Severidad == "CRITICAL" || r.Severidad == "HIGH" {
			out = append(out, r)
		}
	}
	bloquean, _, _ := aplicarExcepciones(out, time.Now())
	return bloquean
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

// Opciones es lo que hay que saber para auditar. Va en struct porque los
// campos crecieron y `Auditar(ctx, a, b, c, d)` ya no decía qué era cada cosa.
type Opciones struct {
	// DirMotores es donde viven los binarios que instalamos.
	DirMotores string
	// DirPython es el site-packages donde pip dejó los motores; vacío si no se
	// sabe (entonces se omite Y SE DICE, en vez de dar por limpio lo que no se
	// miró — ese silencio es justo el fallo que este proyecto lleva persiguiendo).
	DirPython string
	// PaquetesPython son los nombres de NUESTROS paquetes y sus dependencias,
	// normalizados a minúsculas con guiones.
	//
	// Sin esta lista la auditoría acusaba de lo ajeno: en un site-packages de
	// usuario conviven 83 paquetes y sólo 71 son nuestra clausura. `cryptography`
	// salía como "motor de Python" nuestro con un CVE alto, y no lo instalamos
	// nosotros — habría tumbado el CI por algo que no repartimos. Al revés
	// tampoco vale: `mcp` sí es dependencia de semgrep, y quitar el
	// site-packages entero para evitar el ruido nos habría dejado ciegos ahí.
	//
	// Vacía significa "no pude distinguirlos", y entonces se omite con motivo.
	// No filtrar sería acusar de lo ajeno; escanear a ciegas sería no mirar.
	PaquetesPython []string
	// BinTrivy vacío = el trivy del directorio de motores.
	BinTrivy string
	// Ahora existe para poder probar la caducidad de las excepciones sin
	// esperar a que llegue la fecha. Cero = el reloj de verdad.
	Ahora time.Time
}

// Auditar escanea con trivy los motores descargables y los paquetes de Python.
func Auditar(ctx context.Context, op Opciones) (Auditoria, error) {
	var a Auditoria
	dirMotores, dirPython := op.DirMotores, op.DirPython
	binTrivy := op.BinTrivy
	if binTrivy == "" {
		// Sin directorio de motores no se audita NADA, y por el mismo motivo
		// que en Verificar: filepath.Join("", "trivy.exe") no da una ruta
		// vacía, deja "trivy.exe" RELATIVO, que se resuelve contra el
		// directorio de trabajo — el repo analizado. Pero aquí es peor que
		// allí: Verificar sólo LEE el binario para firmarlo, y esto lo
		// EJECUTA.
		//
		// Hoy el único llamador se guarda antes de llamar, así que no es
		// alcanzable. Da igual: el invariante es de esta función, no de quien
		// la llama, y ese es exactamente el argumento con el que se puso la
		// guarda dentro de Verificar. Dejarla fuera aquí sería sostener el
		// principio sólo donde ya dolía.
		if dirMotores == "" {
			return a, fmt.Errorf("sin directorio de motores no hay auditoría posible: " +
				"no se pudo resolver dónde están instalados")
		}
		binTrivy = filepath.Join(dirMotores, "trivy.exe")
	}
	if _, err := os.Stat(binTrivy); err != nil {
		return a, fmt.Errorf("sin trivy no hay auditoría posible: %w", err)
	}

	objetivos := map[string]string{} // nombre → ruta
	for nombre, motor := range cargado.Motores {
		// Por rutaInstalada y no por "<nombre>.exe": los motores de Java no son
		// ejecutables — google-java-format es un .jar y PMD un árbol de 104 —, así
		// que buscarlos como pmd.exe los daba por no instalados estando ahí, y la
		// auditoría los saltaba sin que se notara. Es el mismo campo que ya usa
		// `codeguard engines` para verificar sus hashes; sólo faltaba mirarlo aquí.
		//
		// Se recorren TODAS las versiones conocidas porque durante una
		// actualización conviven dos, y la vieja también está instalada y también
		// se ejecuta.
		// Por ruta y no por versión: gitleaks y trivy se instalan siempre como
		// `<nombre>.exe`, así que todas sus versiones del manifiesto resuelven al
		// MISMO archivo y sólo hay una instalada. Recorrerlas sin más escaneaba el
		// binario dos veces y etiquetaba uno con la versión de la otra — una
		// etiqueta que miente es peor que no ponerla, porque manda a subir una
		// versión que ya estaba instalada.
		//
		// Los motores de Java sí llevan la versión en la ruta (pmd-bin-7.26.0), y
		// ahí las rutas son distintas de verdad: dos conviven durante una
		// actualización y las dos se ejecutan, así que se auditan las dos.
		vistas := map[string]bool{}
		for _, v := range motor.Versiones {
			relativa := rutaInstalada(nombre, v)
			ruta := filepath.Join(dirMotores, relativa)
			if vistas[strings.ToLower(ruta)] {
				continue
			}
			if _, err := os.Stat(ruta); err != nil {
				continue
			}
			vistas[strings.ToLower(ruta)] = true
			etiqueta := nombre
			if v.Instalado != "" {
				etiqueta = nombre + " " + v.Version
			}
			objetivos[etiqueta] = ruta
		}
		if len(vistas) == 0 {
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
	const python = "motores de Python"
	switch {
	case dirPython == "":
		a.Omitidos = append(a.Omitidos, python+" (no sé dónde instaló pip)")
	case len(op.PaquetesPython) == 0:
		a.Omitidos = append(a.Omitidos, python+" (no pude distinguir nuestros paquetes de los demás del site-packages)")
	default:
		if _, err := os.Stat(dirPython); err == nil {
			objetivos[python] = dirPython
		} else {
			a.Omitidos = append(a.Omitidos, python+" (no encuentro site-packages)")
		}
	}
	nuestros := map[string]bool{}
	for _, p := range op.PaquetesPython {
		nuestros[normalizarPaquete(p)] = true
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
		if nombre == python {
			riesgos = soloNuestros(riesgos, nuestros)
		}
		a.Escaneados = append(a.Escaneados, nombre)
		a.Riesgos = append(a.Riesgos, riesgos...)
	}

	var graves []Riesgo
	for _, r := range a.Riesgos {
		if r.Severidad == "CRITICAL" || r.Severidad == "HIGH" {
			graves = append(graves, r)
		}
	}
	ahora := op.Ahora
	if ahora.IsZero() {
		ahora = time.Now()
	}
	_, a.Aceptados, a.AvisosExcepciones = aplicarExcepciones(graves, ahora)
	return a, nil
}

// soloNuestros descarta lo que vive en el mismo site-packages pero no
// instalamos nosotros. Responder por el CVE de un paquete ajeno es tan malo
// como callarse el propio: la primera vez que la compuerta acuse de algo que no
// se puede arreglar tocando CodeGuard, deja de creérsela quien la lee.
func soloNuestros(rs []Riesgo, nuestros map[string]bool) []Riesgo {
	var out []Riesgo
	for _, r := range rs {
		if nuestros[normalizarPaquete(r.Paquete)] {
			out = append(out, r)
		}
	}
	return out
}

// normalizarPaquete aplica la regla de PyPI: mayúsculas y los separadores
// `.`, `_` y `-` son equivalentes. `ruamel.yaml.clib` y `typing_extensions`
// llegan escritos de las dos formas según quién los nombre.
func normalizarPaquete(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	n = strings.NewReplacer(".", "-", "_", "-").Replace(n)
	for strings.Contains(n, "--") {
		n = strings.ReplaceAll(n, "--", "-")
	}
	return n
}

// El subcomando es `rootfs`, no `fs`, y la diferencia no es cosmética: con `fs`
// esta auditoría no miraba NADA. `fs` busca manifiestos de proyecto (go.mod,
// package-lock.json, pom.xml) porque está pensado para código fuente; `rootfs`
// busca artefactos ya instalados —binarios de Go con su lista de módulos
// dentro, jars, site-packages— que es exactamente lo que nosotros repartimos.
//
// Con `fs` los cinco artefactos daban "0 objetivos, 0 vulnerabilidades" y la
// auditoría imprimía su visto bueno. Con `rootfs`, los mismos cinco archivos
// sin tocar dan 88 hallazgos. Se descubrió metiéndole un log4j-core 2.14.1 de
// control: si el escáner no encuentra Log4Shell, su "limpio" no vale nada. Todo
// escáner nuevo entra con un control así, porque la única diferencia entre
// "está limpio" y "no miré" es una prueba que falle cuando debe fallar.
func escanear(ctx context.Context, binTrivy, objetivo, nombre string) ([]Riesgo, error) {
	cmd := comandoIdentidad(ctx, binTrivy,
		"rootfs", "--scanners", "vuln", "--format", "json", "--quiet", "--skip-db-update", objetivo)
	salida, err := proc.Correr(ctx, cmd, proc.MaxSalida)
	if err != nil && len(salida.Stdout) == 0 {
		return nil, fmt.Errorf("trivy no pudo mirarlo: %w", err)
	}
	var res salidaTrivy
	if err := json.Unmarshal(salida.Stdout, &res); err != nil {
		return nil, fmt.Errorf("salida de trivy ilegible")
	}
	// Un escaneo sin un solo objetivo es "no pude mirarlo", no "está limpio".
	// Es la misma trampa que el PMD que escribe files:[] y sale con 1, y la
	// razón de que este agujero durara: por fuera son idénticos.
	if len(res.Results) == 0 {
		return nil, fmt.Errorf("trivy no reconoció nada analizable dentro")
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
