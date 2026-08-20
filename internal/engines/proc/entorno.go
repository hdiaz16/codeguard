package proc

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"codeguard/internal/secreto"
)

// El daemon guarda la API key del modelo en su entorno. Pasarle os.Environ()
// a cada motor se la entregaba entera a gitleaks, semgrep, trivy, squawk, tsc,
// ruff y mypy — siete binarios de terceros que no tienen ningún motivo para
// verla. Ninguno de ellos habla con el modelo.
//
// Por eso el entorno se arma con una lista de lo permitido y no quitando lo
// peligroso: una lista de prohibidos deja pasar la siguiente variable secreta
// que alguien añada, y esa es justo la que no queremos regalar.

// permitidas son las variables que los motores necesitan de verdad. Cada una
// está aquí porque algo se rompe sin ella, no por si acaso.
//
// ⚠️ ANTES DE QUITAR UNA DE AQUÍ, lee esto. Desde que el hook falla CERRADO
// cuando no puede leer lo que está preparado (H041, hook.go: un error de
// gitdiff.Staged es os.Exit(1)) y desde que git corre con este entorno acotado
// (gitdiff.go: cmd.Env = EntornoGit()), las dos cosas se multiplican: una
// variable que git necesite y no esté en esta lista ya NO produce una
// degradación silenciosa, produce un COMMIT BLOQUEADO — en todas las máquinas y
// en cada commit, hasta que alguien lo diagnostique.
//
// Antes de esos dos arreglos, el mismo error salía por el otro extremo: el hook
// se rendía con un `return nil` y el commit pasaba sin revisar. Ninguno de los
// dos autores escribió que la combinación cambia lo que cuesta equivocarse
// aquí, así que queda escrito: esta lista dejó de ser una optimización y pasó a
// estar en el camino crítico de cada commit. Las de git —PATH, SYSTEMROOT,
// USERPROFILE, HOMEDRIVE, HOMEPATH, HOME, APPDATA, LOCALAPPDATA, TEMP— son las
// que hay que tocar con más cuidado; las GIT_* propias van por EntornoGit y no
// por esta lista.
var permitidas = map[string]bool{
	// Windows no arranca un proceso sin esto.
	"SYSTEMROOT": true, "WINDIR": true, "COMSPEC": true, "PATHEXT": true,
	"SYSTEMDRIVE": true, "PROGRAMFILES": true, "PROGRAMFILES(X86)": true,
	"PROGRAMDATA": true, "COMMONPROGRAMFILES": true,
	"NUMBER_OF_PROCESSORS": true, "PROCESSOR_ARCHITECTURE": true, "OS": true,

	// Encontrar los binarios y escribir temporales.
	"PATH": true, "TEMP": true, "TMP": true,

	// Perfil del usuario: trivy cachea su base de vulnerabilidades ahí, y git
	// lee la configuración global desde el home.
	"USERPROFILE": true, "HOMEDRIVE": true, "HOMEPATH": true, "HOME": true,
	"LOCALAPPDATA": true, "APPDATA": true, "USERNAME": true,

	// Cadenas de herramientas.
	"GOPATH": true, "GOROOT": true, "GOCACHE": true, "GOMODCACHE": true,
	"GOFLAGS": true, "GOPROXY": true, "GONOSUMDB": true, "GONOSUMCHECK": true,
	"NODE_PATH": true, "NODE_OPTIONS": true, "NPM_CONFIG_CACHE": true,
	"DOTNET_ROOT": true, "DOTNET_CLI_TELEMETRY_OPTOUT": true, "NUGET_PACKAGES": true,
	"JAVA_HOME":  true,
	"PYTHONPATH": true, "PYTHONHOME": true, "VIRTUAL_ENV": true,
	"PYTHONUTF8": true, "PYTHONIOENCODING": true,
	// MYPYPATH es el PYTHONPATH de mypy: donde busca los stubs que no vienen
	// con el paquete. Filtrarla haría que mypy no encontrara los stubs propios
	// del equipo y llenara el informe de import-not-found que sólo existen
	// porque le quitamos la variable.
	"MYPYPATH": true,

	// Redes corporativas con proxy: sin esto trivy no baja su base.
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true,
	"REQUESTS_CA_BUNDLE": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
	"NODE_EXTRA_CA_CERTS": true,
}

// RefrescarPATH añade al PATH de ESTE proceso lo que el registro tenga ahora.
//
// Tiene que actuar sobre el proceso, no sólo sobre el entorno que se pasa a
// cada motor: exec.LookPath y exec.Command resuelven el ejecutable con el PATH
// del proceso e ignoran por completo el cmd.Env que se les prepare. Arreglar
// sólo Entorno no serviría de nada.
//
// Se llama al arrancar la CLI y el daemon. Es idempotente: si el registro no
// aporta nada nuevo, el PATH queda como estaba.
func RefrescarPATH() {
	vigente := pathVigente()
	if vigente == "" {
		return
	}
	actual := os.Getenv("PATH")
	if actual == "" {
		_ = os.Setenv("PATH", vigente)
		return
	}
	_ = os.Setenv("PATH", fusionarPATH(actual, vigente))
}

// fusionarPATH une el PATH actual con el vigente anteponiendo los nuevos segmentos
// y deduplicando sin repeticiones preservando el orden de prioridad de forma idempotente.
func fusionarPATH(actual, vigente string) string {
	var partes []string
	vistos := map[string]bool{}

	agregar := func(lista string) {
		for _, seg := range filepath.SplitList(lista) {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			limpio := filepath.Clean(seg)
			clave := limpio
			if runtime.GOOS == "windows" {
				clave = strings.ToLower(limpio)
			}
			if !vistos[clave] {
				vistos[clave] = true
				partes = append(partes, seg)
			}
		}
	}

	agregar(vigente)
	agregar(actual)
	return strings.Join(partes, string(os.PathListSeparator))
}

// RefrescarVariables trae del registro las variables de usuario que ESTE
// proceso no tiene, y devuelve cuántas incorporó.
//
// Es el mismo problema que RefrescarPATH y tuvo la misma consecuencia invisible.
// La pantalla de configuración guarda la clave del modelo en HKCU\Environment y
// además hace os.Setenv para que el daemon la vea sin reiniciar sesión — lo cual
// funciona para ESE proceso y sólo para él. Cada reinicio del daemon (y hay uno
// por actualización, o sea varios por semana) arrancaba con un entorno que no
// tenía la clave, os.Getenv devolvía vacío, y la capa LLM se apagaba sola: el
// log decía "sin endpoint/API key" y la pantalla de configuración decía "clave
// sin configurar" mientras la clave llevaba días en el registro. La capa
// semántica del producto estuvo dormida por esto, no por falta de credenciales.
//
// Sólo se incorpora lo que falta: una variable que el proceso YA tiene se
// respeta, porque puede venir de una decisión deliberada de la sesión (un venv
// activo, una clave distinta exportada a mano para una prueba).
func RefrescarVariables() int { return incorporar(variablesDeUsuario()) }

// secretoGestionado dice si esa variable la guarda la bóveda del sistema.
//
// Es la barrera que impide resucitar un secreto ya mudado. La bóveda es la
// fuente de verdad desde que la clave del modelo dejó HKCU\Environment: si
// tiene la variable, lo que quede en el registro es un RESTO —de una versión
// anterior, de un instalador, de un borrado que falló—, no una fuente.
//
// Se pregunta a la bóveda en vez de mantener una lista de nombres conocidos
// porque el nombre lo elige el usuario en la pantalla de configuración
// (api_key_env): una lista fija protegería a los proveedores del catálogo y
// dejaría fuera justo al que configuró alguien a mano. Cuesta una lectura de
// credencial por variable candidata, una vez por proceso.
//
// FALLA ABIERTA a propósito: si la bóveda no responde, esto dice "no la
// gestiona" y la variable se importa. Es deliberado y coherente con llm.ClaveDe
// (llm.go:51), que ante el mismo fallo cae a os.Getenv. Fallar cerrada dejaría
// la capa semántica muerta cada vez que advapi32 tenga un mal día, y no le
// quitaría nada a un atacante: quien corre como este usuario puede llamar a
// CredRead igual que nosotros, como dice el doc de internal/secreto.
//
// Lo que no puede ser es que además sea MUDO. Sin el aviso, una bóveda averiada
// desactiva la barrera, la clave vuelve al entorno y no queda rastro de por qué.
func secretoGestionado(nombre string) bool {
	v, err := secreto.Leer(nombre)
	if err != nil && !secreto.NoEncontrado(err) {
		avisoBoveda.Do(func() {
			log.Printf("aviso: no se pudo consultar el Administrador de credenciales "+
				"(%s: %v). Mientras siga así, una clave que quede en el registro puede "+
				"volver al entorno y heredarla los procesos hijos", nombre, err)
		})
	}
	return err == nil && v != ""
}

// avisoBoveda deja que el fallo se cuente UNA vez por proceso.
//
// Sin esto, una bóveda caída no genera un aviso: genera una avalancha. Se
// consulta una vez por variable candidata en cada arranque y una vez por cada
// GIT_* en cada EntornoGit, que son cuatro por análisis — decenas de líneas por
// commit, todas diciendo lo mismo, enterrando al mensaje de al lado. El aviso
// habla del estado de la barrera, no de una variable concreta; la primera que
// falla vale como ejemplo.
var avisoBoveda sync.Once

// incorporar aplica la regla a un conjunto de variables ya leídas. Existe
// aparte para poder probarla sin escribir en el registro del usuario, que es
// justo lo que un test no debe hacer.
//
// Lo que la bóveda gestiona no se incorpora NUNCA, y eso protege a todo el que
// llame aquí. Hace falta en dos caminos reales y distintos: el daemon, que
// migra la clave y no puede volver a metérsela en el entorno en el siguiente
// refresco; y la CLI, que refresca al arrancar y no migra jamás, así que sin
// esta barrera el git de cada commit heredaba la clave mientras existiera la
// copia del registro.
func incorporar(vars map[string]string) int {
	n := 0
	for clave, valor := range vars {
		if _, ya := os.LookupEnv(clave); ya {
			continue
		}
		if secretoGestionado(clave) {
			continue
		}
		if os.Setenv(clave, valor) == nil {
			n++
		}
	}
	return n
}

// Entorno arma el entorno de un motor: sólo lo permitido, más lo que se le
// pase. Los extra van en la forma "CLAVE=valor" y siempre ganan.
func Entorno(extra ...string) []string {
	out := make([]string, 0, len(permitidas)+len(extra))
	puestas := map[string]bool{}
	for _, e := range extra {
		if i := strings.IndexByte(e, '='); i > 0 {
			puestas[strings.ToUpper(e[:i])] = true
		}
	}
	for _, e := range os.Environ() {
		i := strings.IndexByte(e, '=')
		if i <= 0 {
			continue
		}
		clave := e[:i]
		if puestas[strings.ToUpper(clave)] {
			continue // lo pisa un extra
		}
		if permitidas[strings.ToUpper(clave)] {
			out = append(out, e)
		}
	}
	return append(out, extra...)
}

// EntornoGit es Entorno más las variables GIT_* de este proceso.
//
// git necesita un trato distinto del resto de motores por una razón concreta:
// las GIT_* le dicen QUÉ está mirando. Cuando git lanza el hook de un `git
// commit -a` prepara un índice temporal y lo anuncia en GIT_INDEX_FILE; si esa
// variable no llega, `git diff --cached` lee el índice real y analizaríamos un
// conjunto de cambios distinto del que se está commiteando. Una compuerta que
// revisa el archivo equivocado y no se queja es peor que no tenerla.
//
// El prefijo se acepta entero en vez de enumerar nombres porque la lista de
// GIT_* que git fija para un hook depende de la versión y del subcomando:
// olvidar una se paga con un análisis silenciosamente incorrecto, y aquí el
// destinatario es git, que ya tiene acceso completo al repositorio. Lo que no
// se relaja es el secreto: un nombre GIT_* que la bóveda gestione se queda
// fuera igual.
//
// El precio de aceptar el prefijo entero, dicho en voz alta: por ahí pasan
// GIT_SSH_COMMAND, GIT_EXTERNAL_DIFF, GIT_PROXY_COMMAND y GIT_ASKPASS, que son
// vectores de EJECUCIÓN — git corre lo que digan. No es una regresión (antes de
// acotar el entorno pasaba eso y todo lo demás) y los diffs van con
// --no-ext-diff, pero conviene saberlo antes de dar por hecho que "acotado"
// significa "inofensivo": vienen del entorno del propio usuario, así que el día
// que un llamador de EntornoGit reciba variables de otra procedencia, esto hay
// que revisarlo.
func EntornoGit() []string {
	out := Entorno()
	for _, e := range os.Environ() {
		i := strings.IndexByte(e, '=')
		if i <= 0 {
			continue
		}
		clave := e[:i]
		if !strings.HasPrefix(strings.ToUpper(clave), "GIT_") {
			continue
		}
		if permitidas[strings.ToUpper(clave)] {
			continue // ya la puso Entorno
		}
		if secretoGestionado(clave) {
			continue // el prefijo abre la puerta a git, no a la bóveda
		}
		out = append(out, e)
	}
	return out
}

// Filtradas cuenta cuántas variables se quedaron fuera. Sirve para poder
// decirlo en el diagnóstico en vez de que sea invisible.
func Filtradas() int {
	n := 0
	for _, e := range os.Environ() {
		i := strings.IndexByte(e, '=')
		if i > 0 && !permitidas[strings.ToUpper(e[:i])] {
			n++
		}
	}
	return n
}
