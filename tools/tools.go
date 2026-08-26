//go:build tools

// El módulo de herramientas: los motores que COMPILAMOS (staticcheck,
// govulncheck, gosec) se construyen desde aquí y no con `go install modulo@version`,
// porque sus go.mod fijan pisos de dependencias que a veces van por detrás de
// las correcciones de seguridad — medido el 2026-08-22: staticcheck v0.8.1
// seleccionaba x/mod v0.35.0 y govulncheck v1.7.0 traía v0.39.0, con dos CVE
// HIGH corregidos en v0.40.0. Compilando desde este módulo, MVS toma el
// máximo de los requisitos y nuestro go.sum firma el resultado completo.
//
// actionlint NO cabe aquí, y es medido: exige go.yaml.in/yaml/v4 rc.3 y gosec
// exige rc.6, versión en la que esa API cambió — con el máximo de MVS,
// actionlint deja de compilar («undefined: yaml.ParserError»). Los dos no
// caben en un módulo y actionlint no tiene versión más nueva, así que se
// instala con su PROPIO grafo (`go install …@versión`, marcado «aislado» en
// motores.json). Pierde el MVS-máximo de este módulo; a cambio existe.
//
// El paquete no se compila nunca (build tag tools): los imports en blanco
// existen solo para que `go mod tidy` conserve las dependencias.
package tools

import (
	_ "github.com/securego/gosec/v2/cmd/gosec"
	_ "golang.org/x/mod/module"
	_ "golang.org/x/vuln/cmd/govulncheck"
	_ "honnef.co/go/tools/cmd/staticcheck"
)
