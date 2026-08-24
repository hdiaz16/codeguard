package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/engines/identidad"
	"codeguard/internal/engines/proc"
	"codeguard/internal/instalacion"
)

// DirMotores es donde el instalador deja los binarios descargables.
//
// La resuelve internal/instalacion, que es la única copia: esta función y la
// homónima de internal/engines/linters eran la misma ruta escrita dos veces
// —internal/ no puede importar cmd/— y las dos compartían un agujero de
// ejecución de código. Devuelve "" si no hay directorio resoluble, y eso
// significa "no hay motores", nunca "busca en el directorio actual".
func DirMotores() string { return instalacion.DirMotores() }

func enginesCmd() *cobra.Command {
	var auditar bool
	cmd := &cobra.Command{
		Use:   "engines",
		Short: "Verifica que los motores instalados sean los que publicaron sus autores",
		Long: "Compara el SHA-256 de cada motor descargable contra los hashes " +
			"publicados por sus autores en los checksums de cada release.\n\n" +
			"Los motores de Python (semgrep, squawk, ruff, mypy) no aparecen: los instala " +
			"pip contra PyPI con sus propias firmas, no los distribuimos nosotros.",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := DirMotores()
			// Sin directorio resoluble no se verifica NADA: mirar el directorio
			// actual daría por "motor instalado" cualquier .exe que trajera el
			// repo en el que estás parado, que es lo contrario de lo que hace
			// este comando.
			if dir == "" {
				return fmt.Errorf("no se pudo resolver %%LOCALAPPDATA%%: sin esa variable no hay directorio de motores que verificar")
			}
			if auditar {
				return auditarMotores(dir)
			}
			fmt.Println("motores en", dir)
			fmt.Println()

			problemas := 0
			for _, r := range identidad.Verificar(dir) {
				etiqueta := r.Motor
				if r.Critico {
					etiqueta += " (crítico)"
				}
				switch r.Estado {
				case identidad.Verificado:
					fmt.Printf("  ✓ %-20s v%s — coincide con el binario publicado\n", etiqueta, r.Version)
				case identidad.NoArranca:
					// Ni ✓ ni ✗: es el binario publicado (el hash cuadra) pero no
					// corre aquí. Y NO suma a `problemas`, porque el código de
					// salida de este comando es una compuerta de cadena de
					// suministro en el CI: un JDK viejo no es un binario alterado,
					// y confundirlos convierte "actualiza tu JDK" en "alguien te
					// cambió un motor".
					fmt.Printf("  ! %-20s v%s — es el binario publicado, pero NO ARRANCA aquí\n", etiqueta, r.Version)
					fmt.Printf("      %s\n", r.Detalle)
				case identidad.Ausente:
					fmt.Printf("  · %-20s no instalado\n", etiqueta)
				default:
					problemas++
					fmt.Printf("  ✗ %-20s %s\n", etiqueta, r.Detalle)
					if r.SHA256 != "" {
						fmt.Printf("      instalado: %s\n", r.SHA256)
						for _, v := range identidad.VersionesConocidas(r.Motor) {
							fmt.Printf("      esperado:  %s  (v%s)\n", v.SHA256Exe, v.Version)
						}
					}
				}
			}

			fmt.Println()
			fmt.Println("Contención con la que corren (medida ahora con una sonda, no recitada):")
			// Hasta W4 este bloque MENTÍA: «✓ job object» era texto fijo aunque
			// contener llevara años fallando, y el ✗ del token ni contaba como
			// problema (t.107, hecho #2 del mapa). Ahora se lanza un hijo trivial
			// por proc.Correr y se imprime LO QUE REPORTÓ.
			ctxSonda, cancelSonda := context.WithTimeout(cmd.Context(), 15*time.Second)
			defer cancelSonda()
			ectx, rec := proc.ConRecolector(ctxSonda)
			sonda := exec.CommandContext(ectx, "cmd", "/c", "exit", "0")
			sonda.Env = proc.Entorno()
			_, errSonda := proc.Correr(ectx, sonda, 1<<20)
			c, hubo := rec.Resultado()
			if errSonda != nil || !hubo {
				problemas++
				fmt.Printf("  ✗ sonda de contención  no se pudo medir: %v\n", errSonda)
			} else {
				faceta := func(ok bool, nombre, bien, mal string) {
					if ok {
						fmt.Printf("  ✓ %-20s %s\n", nombre, bien)
					} else {
						problemas++
						fmt.Printf("  ✗ %-20s %s\n", nombre, mal)
					}
				}
				faceta(c.TokenRestringido, "token restringido",
					"sin privilegios salvo recorrer directorios",
					"NO disponible: los motores corren con los privilegios completos de tu sesión")
				faceta(c.Job, "job object",
					"tope de memoria y de procesos aplicados",
					"NO se pudo crear: sin topes de memoria ni de procesos")
				faceta(c.MatarileArbol, "muerte del árbol",
					"al vencer el plazo muere el árbol entero, nietos incluidos",
					"solo muere la raíz al vencer el plazo: los nietos pueden sobrevivir huérfanos")
				faceta(c.LimitesUI, "sin interfaz",
					"sin portapapeles, escritorio ni ventanas de otros",
					"las restricciones de interfaz no se aplicaron")
				if c.Detalle != "" {
					fmt.Printf("      motivo: %s\n", c.Detalle)
				}
			}
			fmt.Printf("  ✓ entorno acotado      %d variables retenidas (la API key del modelo no viaja)\n", proc.Filtradas())
			fmt.Println("  · sistema de archivos  sin restringir: un motor tiene que leer el repo")

			if problemas == 0 {
				fmt.Println("\ntodos los motores instalados son los publicados por sus autores")
				return nil
			}
			fmt.Println("\nUn motor que no reconocemos puede ser:")
			fmt.Println("  1. una versión más nueva que instalaste a mano — actualiza el manifiesto")
			fmt.Println("     (internal/engines/identidad/motores.json) con el hash de su release")
			fmt.Println("  2. un binario alterado — bórralo y reinstala con install.ps1")
			fmt.Println("\nHasta aclararlo, trata sus resultados con reserva: un gitleaks")
			fmt.Println("manipulado puede no reportar ni un solo secreto.")
			// La guía queda en stdout; el veredicto corto va por el error, que main
			// imprime en stderr y convierte en salida ≠0 para la compuerta del CI.
			return errors.New("hay motores no reconocidos: revisa el detalle de arriba")
		},
	}
	cmd.Flags().BoolVar(&auditar, "auditar", false,
		"escanea con trivy los motores que distribuimos, en busca de CVEs propios")
	return cmd
}

// auditarMotores mira si lo que NOSOTROS instalamos trae vulnerabilidades.
//
// `codeguard engines` responde "¿este binario es el que publicó su autor?".
// Esto responde la otra mitad: "¿y lo que publicó su autor está sano?". Un
// motor puede coincidir con su hash a la perfección y arrastrar un CVE crítico
// dentro; el hash sólo prueba que nadie lo tocó por el camino.
//
// Devuelve error si hay algo crítico o alto, para que el CI pueda usarlo como
// compuerta: una herramienta de seguridad que reparte binarios sin mirarlos
// pide una confianza que no se ganó. Se devuelve y no se sale con os.Exit
// porque el defer cancel() de abajo tiene que correr siempre: salir aquí
// dejaba el contexto sin cancelar y los subprocesos de trivy huérfanos.
func auditarMotores(dir string) error {
	fmt.Println("auditando lo que CodeGuard instala en tu equipo…")
	fmt.Println()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	a, err := identidad.Auditar(ctx, identidad.Opciones{
		DirMotores:     dir,
		DirPython:      dirPaquetesPython(ctx),
		PaquetesPython: clausuraPaquetesPython(ctx),
	})
	if err != nil {
		return err
	}
	if len(a.Escaneados) > 0 {
		fmt.Println("escaneados:", strings.Join(a.Escaneados, ", "))
	}
	// Lo que no se pudo mirar se dice SIEMPRE: dar por limpio lo que no se
	// revisó es el fallo que este proyecto lleva un mes persiguiendo.
	for _, o := range a.Omitidos {
		fmt.Println("  · sin revisar:", o)
	}
	fmt.Println()

	// Las excepciones se imprimen SIEMPRE y con quién las firmó. Un riesgo
	// aceptado que no se ve es indistinguible de un riesgo que nadie detectó.
	if len(a.Aceptados) > 0 {
		fmt.Printf("%d riesgo(s) aceptado(s) por escrito:\n", len(a.Aceptados))
		porFirma := map[string][]identidad.Aceptado{}
		var orden []string
		for _, ac := range a.Aceptados {
			k := fmt.Sprintf("%s / %s — aceptado por %s hasta %s",
				ac.Excepcion.Artefacto, ac.Excepcion.Objetivo(), ac.Excepcion.AceptadaPor, ac.Excepcion.Hasta)
			if _, ya := porFirma[k]; !ya {
				orden = append(orden, k)
			}
			porFirma[k] = append(porFirma[k], ac)
		}
		for _, k := range orden {
			fmt.Printf("  ~ %s (%d hallazgo(s))\n", k, len(porFirma[k]))
			fmt.Printf("    %s\n", porFirma[k][0].Excepcion.Motivo)
		}
		fmt.Println()
	}
	// Una excepción caducada, sin firma o que ya no cubre nada es alguien
	// creyendo que un riesgo está cubierto cuando no lo está. Se dice aparte.
	for _, av := range a.AvisosExcepciones {
		fmt.Println("  ! excepción inservible:", av)
	}
	if len(a.AvisosExcepciones) > 0 {
		fmt.Println()
	}

	graves := a.Graves()
	if len(a.Riesgos) == 0 {
		fmt.Println("✓ sin vulnerabilidades conocidas en los motores que distribuimos")
		return nil
	}
	fmt.Printf("%d vulnerabilidad(es) en total, %d crítica(s)/alta(s) sin aceptar\n\n",
		len(a.Riesgos), len(graves))
	for _, r := range graves {
		arreglo := "sin versión corregida publicada"
		if r.Corregida != "" {
			arreglo = "corregida en " + r.Corregida
		}
		fmt.Printf("  ✗ %-18s %s [%s] en %s@%s — %s\n",
			r.Artefacto, r.CVE, r.Severidad, r.Paquete, r.Version, arreglo)
	}
	if len(graves) == 0 {
		fmt.Println("ninguna crítica ni alta sin aceptar: no bloquea el reparto, pero conviene subir el resto")
		return nil
	}
	fmt.Println("\nSube la versión del motor en internal/engines/identidad/motores.json")
	fmt.Println("(con el hash de la release nueva) y vuelve a construir el instalador.")
	fmt.Println("Si no hay versión corregida, la salida no es bajar el umbral: es")
	fmt.Println("firmar el riesgo en internal/engines/identidad/excepciones.json,")
	fmt.Println("con motivo y fecha de caducidad.")
	return errors.New("hay vulnerabilidades críticas o altas sin aceptar en los motores que distribuimos")
}

// dirPaquetesPython pregunta a Python dónde instaló pip los paquetes de
// usuario, en vez de adivinar la ruta: depende de la versión de Python.
// Recibe el ctx de la auditoría porque un intérprete colgado (instalación
// rota, antivirus escaneando) no puede dejar la auditoría esperando para
// siempre: al expirar el plazo el subproceso muere. Igual que la clausura.
func dirPaquetesPython(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "python", "-c",
		"import sysconfig; print(sysconfig.get_path('purelib', 'nt_user'))").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// guionClausura le pregunta a Python qué paquetes son nuestros: los cuatro que
// instalamos y todo lo que arrastran. Se resuelve con importlib.metadata, que
// lee lo REALMENTE instalado, y no con una lista escrita a mano que envejece en
// cuanto semgrep cambia una dependencia.
//
// Los marcadores de entorno se evalúan (`req.marker.evaluate()`) porque media
// dependencia de semgrep es condicional —`;python_version<"3.11"`— y contarlas
// todas metería en la clausura paquetes que en esta máquina no existen.
const guionClausura = `
import importlib.metadata as md, sys
try:
    from packaging.requirements import Requirement
except Exception:
    sys.exit(2)
raiz = ["semgrep", "squawk-cli", "ruff", "mypy"]
vistos, cola = set(), list(raiz)
while cola:
    nombre = cola.pop()
    clave = nombre.lower().replace("_", "-").replace(".", "-")
    if clave in vistos:
        continue
    vistos.add(clave)
    try:
        dist = md.distribution(nombre)
    except Exception:
        continue
    for bruto in (dist.requires or []):
        try:
            req = Requirement(bruto)
        except Exception:
            continue
        if req.marker and not req.marker.evaluate():
            continue
        cola.append(req.name)
print("\n".join(sorted(vistos)))
`

// clausuraPaquetesPython devuelve vacío si no se puede resolver, y Auditar lo
// interpreta como "no pude distinguirlos" y lo dice. Lo que NO hace es escanear
// el site-packages entero: ahí conviven los paquetes de todo el mundo, y
// acusarnos de un CVE de `cryptography` que no instalamos nosotros gasta la
// credibilidad de la compuerta igual de rápido que callarse uno propio.
func clausuraPaquetesPython(ctx context.Context) []string {
	cmd := exec.CommandContext(ctx, "python", "-c", guionClausura)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var nombres []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			nombres = append(nombres, l)
		}
	}
	return nombres
}
