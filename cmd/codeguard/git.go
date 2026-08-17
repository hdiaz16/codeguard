package main

import (
	"os/exec"

	"codeguard/internal/engines/proc"
)

// gitCmd arma un git con el entorno acotado. Es el ÚNICO sitio de la CLI donde
// se construye uno.
//
// Existe porque el problema no eran siete descuidos, era uno solo repetido
// siete veces: cada llamador se armaba su propio exec.Command y nada le
// obligaba a fijar cmd.Env, así que todas heredaban os.Environ() entero. Con la
// clave del modelo dentro, porque la CLI llama a proc.RefrescarVariables() al
// arrancar (main.go:42) y eso TRAE del registro las variables que el proceso no
// tiene. Arreglar las siete de una en una dejaba el agujero abierto para la
// octava; con un constructor, el camino seguro es el único que hay, y
// TestTodoGitDeLaCLIPasaPorGitCmd es lo que impide que vuelva a haber otro.
//
// El entorno es EntornoGit y no Entorno, y la diferencia no es cosmética: las
// variables GIT_* le dicen a git QUÉ está mirando. En un `git commit -a`, git
// prepara un índice temporal y lo anuncia en GIT_INDEX_FILE; si se filtra,
// `write-tree` firma el árbol del índice real y el trailer del commit acaba
// afirmando que pasó por CodeGuard un contenido que nunca se analizó. Medido en
// TestArbolPreparadoMiraElIndiceQueSeEstaCommiteando, que es justo la prueba
// que se pone roja si alguien cambia esto por proc.Entorno().
//
// Lo que NO se acota es el directorio de trabajo ni los argumentos: cada
// llamador sigue pasando su `-C <repo>` como antes. Aquí sólo cambia lo que el
// hijo ve del entorno.
func gitCmd(args ...string) *exec.Cmd {
	c := exec.Command("git", args...)
	c.Env = proc.EntornoGit()
	return c
}
