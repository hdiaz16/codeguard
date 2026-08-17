package daemon

import (
	"os/exec"

	"codeguard/internal/engines/proc"
)

// NoDisponible es una capa que el repo SÍ activaría y que esta máquina no puede
// ejecutar.
type NoDisponible struct {
	Motor  string `json:"motor"`
	Falta  string `json:"falta"`  // el ejecutable que no aparece
	Motivo string `json:"motivo"` // dicho para quien lo va a leer, no para un log
}

// requisitos dice, por motor, qué ejecutable invoca de verdad.
//
// "Aplica" y "puede correr" son DOS preguntas, y hasta aquí sólo existía la
// primera. Medido por el validador sobre 10 repos reales: 5 sobre-declaraban.
// El más claro es un repo de TypeScript donde tsc aplica y no está instalado —
// decirle a su dueño "3 capas vigilan tu repo" cuando la capa de TypeScript no
// existe es peor que decirle 2, porque el 3 no se puede desmentir mirando.
//
// Cada valor es el ejecutable que ese motor pasa a exec, LITERAL. Poner "node"
// donde el motor llama a "npx" volvería a ser lo de siempre: dos criterios para
// la misma pregunta, discrepando el día menos pensado. La cadena vacía significa
// "no se comprueba", y hoy sólo la tiene gofmt, que formatea dentro de este
// mismo proceso y no puede faltar.
//
// Es un mapa a mano y eso es una deuda asumida: lo correcto de verdad sería que
// cada motor declarase su requisito en la interfaz, y eso toca los 16. Mientras
// tanto, TestCadaMotorDeclaraQueNecesitaParaCorrer impide que se quede viejo en
// silencio, que es lo único que lo haría peligroso.
//
// No es var por capricho: los tests lo sustituyen para no depender de qué haya
// instalado en el disco de quien compile.
var requisitos = map[string]string{
	"semgrep":     "semgrep",
	"squawk":      "squawk",
	"trivy":       "trivy",
	"govulncheck": "govulncheck",
	"staticcheck": "staticcheck",
	"ruff":        "ruff",
	"mypy":        "mypy",
	"govet":       "go",
	"gofmt":       "", // formatea en proceso: no hay nada que buscar
	// tsc y eslint NO se comprueban, y es una decisión, no un olvido.
	//
	// Su ejecutable no es de la máquina sino DEL PROYECTO: binarioJS busca
	// node_modules/.bin/<tool>.cmd del directorio que tiene el manifiesto y sólo
	// cae a `npx.cmd --no-install` si no está. Comprobar "npx" aquí sería
	// mentir hacia el lado caro —medido: en esta máquina npx existe y aun así
	// `--no-install` falla si el paquete no está en el repo—, y comprobar el
	// node_modules de la raíz sería inventar un criterio distinto del que usa el
	// motor, que es el fallo que este trabajo entero viene a corregir.
	//
	// Así que hoy no se dicen: el panel no promete que puedan correr, pero
	// tampoco avisa de que no pueden. Se queda corto a sabiendas. Arreglarlo de
	// verdad es exportar desde `linters` la misma resolución por proyecto que ya
	// usa binarioJS, y eso es trabajo aparte.
	"tsc":                "",
	"eslint":             "",
	"dotnet-format":      "dotnet",
	"dotnet-build":       "dotnet",
	"dotnet-vuln":        "dotnet",
	"google-java-format": "java",
	"pmd":                "java",
}

// comoInstalar traduce el ejecutable que falta a la frase que de verdad
// desatasca a quien la lee. Un "no encontré npx" no le dice a nadie qué hacer;
// "instala Node.js" sí.
var comoInstalar = map[string]string{
	"npx":         "instala Node.js y vuelve a abrir la terminal",
	"dotnet":      "instala el SDK de .NET",
	"java":        "instala un JDK 21 o más nuevo",
	"go":          "instala Go",
	"semgrep":     "reinstala el agente: lo trae el instalador",
	"squawk":      "reinstala el agente: lo trae el instalador",
	"ruff":        "reinstala el agente: lo trae el instalador",
	"mypy":        "reinstala el agente: lo trae el instalador",
	"trivy":       "reinstala el agente: lo trae el instalador",
	"gitleaks":    "reinstala el agente: lo trae el instalador",
	"staticcheck": "reinstala el agente: lo trae el instalador",
	"govulncheck": "reinstala el agente: lo trae el instalador",
}

// Disponibilidad devuelve, de las capas que se le pasan, las que esta máquina
// NO puede ejecutar.
//
// Se le pasan las capas DEL REPO y no las 16 a propósito: avisar de un tsc
// ausente a quien no escribe TypeScript es ruido sobre algo que no le afecta, y
// el ruido acaba enseñando a ignorar los avisos que sí importan.
//
// Devuelve sólo las que faltan, no las 16 con su estado: quien pregunta va a
// escribir una línea que empieza por "N de esas M no pueden correr aquí", y esa
// línea desaparece entera cuando la lista viene vacía.
//
// Cuesta microsegundos —es exec.LookPath, que sólo mira el PATH— y por eso se
// puede llamar en cada refresco del panel sin pensarlo. La comprobación cara es
// otra y no está aquí: distinguir "instalado" de "instalado pero no arranca"
// (el jar de google-java-format con un JDK 17) exige lanzar la JVM y cuesta
// entre 9 y 16 segundos, medido. Eso no puede colgar de un refresco del panel;
// va aparte y en segundo plano.
//
// Lo que hoy NO se detecta, dicho para que nadie lo lea como una garantía:
//   - java instalado pero demasiado viejo para el jar (la comprobación cara).
//   - eslint y tsc resueltos por el node_modules del propio repo, que funcionan
//     aunque npx no esté. Se prefiere el falso "no puede" al falso "sí puede":
//     equivocarse por decir de menos se nota y se corrige; equivocarse por
//     prometer de más no se nota nunca.
func Disponibilidad(capasDelRepo []string) []NoDisponible {
	// El PATH del registro, no el que heredó este proceso. El daemon lo refresca
	// al arrancar, pero quien instala un motor DESPUÉS lo hace con el daemon ya
	// vivo: sin esto, el panel seguiría diciendo "no encuentro trivy" sobre un
	// trivy recién instalado hasta que alguien reiniciara el daemon. Y un dev no
	// va a reiniciar el daemon. Es una lectura del registro, así que cabe en cada
	// refresco.
	proc.RefrescarPATH()

	var out []NoDisponible
	for _, motor := range capasDelRepo {
		necesita, conocido := requisitos[motor]
		if !conocido || necesita == "" {
			continue
		}
		if _, err := exec.LookPath(necesita); err == nil {
			continue
		}
		motivo := "no encuentro " + necesita
		if como := comoInstalar[necesita]; como != "" {
			motivo += " — " + como
		}
		out = append(out, NoDisponible{Motor: motor, Falta: necesita, Motivo: motivo})
	}
	return out
}
