package instalacion

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Esta función es el único sitio donde se impone el invariante, así que se
// prueba aquí y no sólo a través de quien la llama: si mañana alguien quita el
// envoltorio de linters o el de cmd/codeguard, la garantía tiene que seguir
// teniendo dueño y prueba.
//
// Lo que se garantiza: o una ruta ABSOLUTA, o "". Nunca una relativa, porque
// una relativa apunta al directorio de trabajo —el repo que se analiza— y de
// ese directorio sale un binario que se ejecuta.
func TestDirMotoresEsAbsolutaOEsNada(t *testing.T) {
	casos := []struct {
		nombre       string
		localappdata string
		quieroVacio  bool
	}{
		{"variable ausente", "", true},
		{"variable en blanco", "   ", true},
		{"valor relativo puesto a mano", `datos\local`, true},
		{"valor relativo con punto", `.`, true},
		{"valor absoluto normal", t.TempDir(), false},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			t.Setenv("LOCALAPPDATA", c.localappdata)
			got := DirMotores()
			if c.quieroVacio {
				if got != "" {
					t.Errorf("LOCALAPPDATA=%q debía dar \"\" y dio %q", c.localappdata, got)
				}
				return
			}
			if !filepath.IsAbs(got) {
				t.Errorf("LOCALAPPDATA=%q dio una ruta relativa: %q", c.localappdata, got)
			}
			if filepath.Base(got) != "engines" {
				t.Errorf("el directorio de motores cambió de sitio: %q", got)
			}
		})
	}
}

func TestElInstaladorNoAceptaSecretosPorArgumento(t *testing.T) {
	texto := instaladorPS1(t)

	bloque := regexp.MustCompile(`(?ms)^param\(\s*(.*?)^\)`).FindStringSubmatch(texto)
	if bloque == nil {
		t.Fatal("install.ps1 no contiene un bloque param reconocible")
	}

	prohibido := regexp.MustCompile(`(?i)\$[^\r\n,]*(?:api.?key|secret|token|password|clave)`)
	if nombre := prohibido.FindString(bloque[1]); nombre != "" {
		t.Fatalf("el instalador expone un posible secreto como argumento: %q", nombre)
	}

	if strings.Contains(strings.ToLower(texto), "--guardar-clave") {
		t.Fatal("el instalador no debe recibir ni reenviar secretos")
	}
}

func TestActualizarNuncaMezclaDosVersionesNiDosDaemons(t *testing.T) {
	texto := instaladorPS1(t)
	posDetener := strings.Index(texto, "\nStop-CodeGuardDaemon\n")
	posTransaccion := strings.Index(texto, "\n$cambios = [System.Collections.Generic.List[object]]::new()")
	posArranqueNormal := strings.LastIndex(texto, "Start-Process \"$Bin\\codeguard-daemon.exe\"")
	if posDetener < 0 || posTransaccion < 0 || posArranqueNormal < 0 {
		t.Fatal("el instalador perdió una etapa del contrato stop → reemplazo → start")
	}
	if !(posDetener < posTransaccion && posTransaccion < posArranqueNormal) {
		t.Fatalf("orden inseguro de actualización: stop=%d transacción=%d start=%d", posDetener, posTransaccion, posArranqueNormal)
	}

	posApagadoIPC := strings.Index(texto, "& $cliAnterior daemon-stop")
	posMatar := strings.Index(texto, "Stop-Process -Force")
	if posApagadoIPC < 0 || posMatar < 0 || posApagadoIPC > posMatar {
		t.Fatal("la actualización debe pedir apagado por IPC antes del kill de compatibilidad")
	}
	for _, prueba := range []string{
		"Rollback en orden inverso",
		"Move-Item -LiteralPath $c.Backup -Destination $c.Target",
		"$procesos.Count -eq 1",
		"throw \"el daemon nuevo no confirmó estado saludable y único",
	} {
		if !strings.Contains(texto, prueba) {
			t.Fatalf("falta la garantía de actualización %q", prueba)
		}
	}
	if regexp.MustCompile(`(?i)Copy-Item[^\r\n]*\$Src[^\r\n]*\$Bin`).MatchString(texto) {
		t.Fatal("un Copy-Item directo Src→Bin puede dejar una mezcla de versiones; debe pasar por stage y swap")
	}
}

func TestElSetupGraficoComparteElMismoContratoDeUpgrade(t *testing.T) {
	texto := archivoDeDist(t, "setup.iss")
	for _, prueba := range []string{
		"function PrepareToInstall(var NeedsRestart: Boolean): String;",
		"DetenerDaemon();",
		"'daemon-stop'",
		"'/F /IM {#MyDaemonExe}'",
		"tasklist /FI \"IMAGENAME eq {#MyDaemonExe}\"",
		"procedure ArrancarYVerificarDaemon();",
		"ArrancarYVerificarDaemon();",
		"doctor --global",
	} {
		if !strings.Contains(texto, prueba) {
			t.Fatalf("setup.iss perdió la garantía de actualización %q", prueba)
		}
	}
	if strings.Index(texto, "'daemon-stop'") > strings.Index(texto, "'/F /IM {#MyDaemonExe}'") {
		t.Fatal("setup.iss mata el daemon antes de pedir el apagado limpio")
	}
	if strings.Contains(texto, "CreateUninstallRegKey=no") || !strings.Contains(texto, "CreateUninstallRegKey=yes") {
		t.Fatal("el setup debe registrar CodeGuard en Aplicaciones instaladas")
	}
	if !strings.Contains(texto, `Type: filesandordirs; Name: "{app}\engines"`) {
		t.Fatal("el desinstalador deja vivo el runtime generado de motores")
	}
	for _, generado := range []string{`{app}\semgrep`, `{app}\wv_*`} {
		if !strings.Contains(texto, `Type: filesandordirs; Name: "`+generado+`"`) {
			t.Fatalf("el desinstalador deja vivo el residuo generado %s", generado)
		}
	}
}

func TestElSetupVisualGobiernaElPATHEnTodoElCicloDeVida(t *testing.T) {
	texto := archivoDeDist(t, "setup.iss")
	contratos := []string{
		"ChangesEnvironment=yes",
		"function ActualizarPathCodeGuard(Instalar: Boolean): Boolean;",
		"RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Actual)",
		"RegWriteExpandStringValue(",
		"(not EsRutaPathDeCodeGuard(Entrada))",
		"ActualizarPathCodeGuard(False)",
		"ActualizarPathCodeGuard(True)",
	}
	for _, contrato := range contratos {
		if !strings.Contains(texto, contrato) {
			t.Errorf("el setup visual perdió el contrato de PATH %q", contrato)
		}
	}
	if strings.Contains(strings.ToLower(texto), "uninsdeletevalue") {
		t.Fatal("el setup no puede borrar el valor PATH entero al desinstalar")
	}
}

func TestLosMotoresSoloSeResuelvenDesdeFuentesOficialesYCerradas(t *testing.T) {
	buildPython := archivoDeDist(t, "build-python-wheelhouse.ps1")
	for _, contrato := range []string{
		`--isolated`, `https://pypi.org/simple`, `files.pythonhosted.org`,
		`--require-hashes`, `--only-binary=:all:`, `--no-index`,
	} {
		if !strings.Contains(buildPython, contrato) {
			t.Fatalf("el wheelhouse Python perdió el contrato %q", contrato)
		}
	}
	engines := archivoDeDist(t, "engines.ps1")
	for _, contrato := range []string{`--isolated`, `--no-index`, `--require-hashes`, `requirements.lock`, `wheelhouse`} {
		if !strings.Contains(engines, contrato) {
			t.Fatalf("el instalador Python perdió el contrato offline %q", contrato)
		}
	}
	if strings.Contains(engines, `pip", "install", "--user`) {
		t.Fatal("los motores Python volvieron a instalarse en el entorno global del usuario")
	}
	posSwapPython := strings.Index(engines, `Move-Item -LiteralPath $stagePy -Destination $runtimePy`)
	posRelinkPython := strings.Index(engines, `"--force-reinstall"`)
	if posSwapPython < 0 || posRelinkPython < posSwapPython {
		t.Fatal("el venv se mueve sin regenerar después los launchers con su ruta final")
	}
	posLimpiezaPython := strings.Index(engines, `-Directory -Filter "python-*"`)
	if posLimpiezaPython < posRelinkPython || !strings.Contains(engines, `$anterior.FullName, $runtimePy`) {
		t.Fatal("una actualización deja runtimes Python antiguos junto al vigente")
	}
	for _, contrato := range []string{
		`$env:GOPROXY = "https://proxy.golang.org"`,
		`$env:GOSUMDB = "sum.golang.org"`,
		`$env:GOPRIVATE = ""`, `$env:GONOSUMDB = ""`, `$env:GOINSECURE = ""`,
		`"--source", "winget"`,
	} {
		if !strings.Contains(engines, contrato) {
			t.Fatalf("el instalador perdió la restricción de fuente oficial %q", contrato)
		}
	}
	setup := archivoDeDist(t, "setup.iss")
	if !strings.Contains(setup, `Source: "python\*"`) {
		t.Fatal("el setup no empaqueta el wheelhouse verificado")
	}

	var catalogo struct {
		Motores map[string]struct {
			Repo      string `json:"repo"`
			Versiones []struct {
				URL string `json:"url"`
			} `json:"versiones"`
		} `json:"motores"`
		Paquetes struct {
			Go map[string]struct {
				Modulo     string `json:"modulo"`
				ModuloRaiz string `json:"modulo_raiz"`
			} `json:"go"`
			Winget      map[string]string `json:"winget"`
			GoToolchain string            `json:"go_toolchain"`
		} `json:"paquetes"`
	}
	raw := []byte(archivoDeIdentidad(t, "motores.json"))
	if err := json.Unmarshal(raw, &catalogo); err != nil {
		t.Fatal(err)
	}
	for nombre, motor := range catalogo.Motores {
		for _, version := range motor.Versiones {
			u, err := url.Parse(version.URL)
			if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "github.com") {
				t.Errorf("%s usa una fuente no oficial o no HTTPS: %q", nombre, version.URL)
				continue
			}
			esperado := "/" + motor.Repo + "/releases/download/"
			if !strings.HasPrefix(strings.ToLower(u.Path), strings.ToLower(esperado)) {
				t.Errorf("%s descarga de un repo distinto al oficial %s: %s", nombre, motor.Repo, u.Path)
			}
		}
	}
	oficialesGo := map[string]string{
		"govulncheck": "golang.org/x/vuln",
		"staticcheck": "honnef.co/go/tools",
		"gosec":       "github.com/securego/gosec/v2",
		"actionlint":  "github.com/rhysd/actionlint",
	}
	if len(catalogo.Paquetes.Go) != len(oficialesGo) {
		t.Fatalf("cambió el conjunto de motores Go sin actualizar su allowlist oficial: %d", len(catalogo.Paquetes.Go))
	}
	for nombre, raiz := range oficialesGo {
		spec, ok := catalogo.Paquetes.Go[nombre]
		if !ok || spec.ModuloRaiz != raiz || !strings.HasPrefix(spec.Modulo, raiz+"/") {
			t.Errorf("%s no apunta al módulo oficial esperado %s: %+v", nombre, raiz, spec)
		}
	}
	if got := catalogo.Paquetes.Winget["shellcheck"]; got != "koalaman.shellcheck" {
		t.Errorf("ShellCheck no usa el identificador oficial fijado: %q", got)
	}
	if catalogo.Paquetes.GoToolchain != "go1.26.6" {
		t.Errorf("toolchain Go no está fijado a la revisión segura esperada: %q", catalogo.Paquetes.GoToolchain)
	}
	if !strings.Contains(engines, `$env:GOTOOLCHAIN = $goToolchain + "+auto"`) {
		t.Error("el instalador no obliga a compilar motores con el toolchain seguro del catálogo")
	}
}

func TestUnaDistribucionNoPuedeSalirConRulepackSinFirma(t *testing.T) {
	build := archivoDeDist(t, "build-dist.ps1")
	if !strings.Contains(build, "una distribucion estable nunca sale sin firma") {
		t.Fatal("build-dist ya no falla explícitamente cuando la firma del rulepack falla")
	}
	if strings.Contains(build, "AVISO: rulepack") && strings.Contains(build, "SIN FIRMAR") {
		t.Fatal("build-dist conserva el antiguo fallback que publicaba rulepacks sin firma")
	}
	if !strings.Contains(build, "codeguard/internal/manifest.ReleaseKeys=$releasePublic") {
		t.Fatal("build-dist firma los rulepacks pero no ancla la pública dentro de los binarios")
	}
}

func instaladorPS1(t *testing.T) string {
	// Un checkout limpio de Git en Windows puede materializar el script con
	// CRLF aunque el blob esté normalizado a LF. El contrato prueba el orden de
	// las etapas, no el formato de finales de línea.
	return strings.ReplaceAll(archivoDeDist(t, "install.ps1"), "\r\n", "\n")
}

func archivoDeDist(t *testing.T, nombre string) string {
	t.Helper()
	_, archivo, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no se pudo localizar el archivo de prueba")
	}

	ruta := filepath.Join(filepath.Dir(archivo), "..", "..", "dist", nombre)
	contenido, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("leer %s: %v", ruta, err)
	}
	return string(contenido)
}

func archivoDeIdentidad(t *testing.T, nombre string) string {
	t.Helper()
	_, archivo, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no se pudo localizar el archivo de prueba")
	}
	ruta := filepath.Join(filepath.Dir(archivo), "..", "engines", "identidad", nombre)
	contenido, err := os.ReadFile(ruta)
	if err != nil {
		t.Fatalf("leer %s: %v", ruta, err)
	}
	return string(contenido)
}
