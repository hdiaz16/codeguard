// genicono escribe el ícono oficial de CodeGuard como .ico multitamaño y una
// tira de previsualización con todos los estados. Se ejecuta a mano cuando
// cambia el diseño del orbe; el resultado se versiona en dist/.
package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"

	"codeguard/internal/orbe"
)

// fondo imita el gris de la barra de tareas oscura de Windows.
var fondo = color.NRGBA{R: 0x20, G: 0x23, B: 0x26, A: 0xFF}

func main() {
	salida := flag.String("out", "dist", "carpeta donde escribir")
	flag.Parse()

	ico, err := orbe.ConstruirICO([]int{16, 24, 32, 48, 64, 128, 256}, "idle")
	if err != nil {
		fmt.Fprintln(os.Stderr, "no se pudo construir el .ico:", err)
		os.Exit(1)
	}
	rutaICO := filepath.Join(*salida, "codeguard.ico")
	if err := os.WriteFile(rutaICO, ico, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%s (%d KB, 7 tamaños)\n", rutaICO, len(ico)/1024)

	// Tira de previsualización: cada estado a 128 px y a 32 px, sobre un fondo
	// oscuro como el de la barra de tareas.
	estados := []string{"idle", "working", "pass", "blocked", "degraded", "offline"}
	const grande, chico, sep = 128, 32, 16
	ancho := len(estados)*(grande+sep) + sep
	alto := grande + chico + 3*sep
	tira := image.NewNRGBA(image.Rect(0, 0, ancho, alto))
	draw.Draw(tira, tira.Bounds(), &image.Uniform{fondo}, image.Point{}, draw.Src)

	for i, e := range estados {
		x := sep + i*(grande+sep)
		draw.Draw(tira, image.Rect(x, sep, x+grande, sep+grande),
			orbe.Dibujar(grande, e), image.Point{}, draw.Over)
		xc := x + (grande-chico)/2
		yc := sep + grande + sep
		draw.Draw(tira, image.Rect(xc, yc, xc+chico, yc+chico),
			orbe.Dibujar(chico, e), image.Point{}, draw.Over)
	}
	rutaPrev := filepath.Join(*salida, "orbe-previsualizacion.png")
	f, err := os.Create(rutaPrev)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Sin comprobar el cierre, un PNG truncado se anunciaba como escrito.
	if err := png.Encode(f, tira); err != nil {
		f.Close()
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "el archivo quedó incompleto:", err)
		os.Exit(1)
	}
	fmt.Println(rutaPrev, "—", len(estados), "estados a 128 px y 32 px")
}
