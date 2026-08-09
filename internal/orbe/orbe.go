package orbe

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Los íconos son el mismo orbe del widget, dibujados en Go: sin assets
// externos y sin que la identidad del agente dependa de un archivo que
// alguien pueda perder. Cada estado usa la paleta que ya define widget.html,
// para que el ícono de la bandeja y el orbe en pantalla sean la misma cosa.

// paleta reproduce las variables --plasma-* del widget: el tono caliente del
// núcleo, el frío del borde y la chispa que ilumina desde arriba a la
// izquierda.
type paleta struct {
	nucleo, borde, chispa color.NRGBA
}

func rgb(hex uint32) color.NRGBA {
	return color.NRGBA{R: uint8(hex >> 16), G: uint8(hex >> 8), B: uint8(hex), A: 0xFF}
}

var paletas = map[string]paleta{
	// idle: niebla de pizarra (paleta MONTAÑA)
	"idle":     {rgb(0x8e979e), rgb(0x565f66), rgb(0xc9d2d8)},
	"working":  {rgb(0xbcc5cc), rgb(0x7d8891), rgb(0xe6ebef)},
	"pass":     {rgb(0x8fd4ac), rgb(0x4a9a70), rgb(0xddf5e8)},
	"blocked":  {rgb(0xc56a55), rgb(0x7e4436), rgb(0xf0b5a4)},
	"degraded": {rgb(0x9e9484), rgb(0x645c50), rgb(0xd8cfc0)},
	"offline":  {rgb(0x565b60), rgb(0x35393d), rgb(0x8a9298)},
}

var cache = map[string][]byte{}

// PNG devuelve el orbe del estado pedido, al tamaño pedido, ya codificado.
func PNG(tamano int, estado string) []byte {
	clave := estado + ":" + string(rune(tamano))
	if b, ok := cache[clave]; ok {
		return b
	}
	var buf bytes.Buffer
	png.Encode(&buf, Dibujar(tamano, estado))
	cache[clave] = buf.Bytes()
	return buf.Bytes()
}

// dibujarOrbe pinta una esfera con luz propia: un núcleo desplazado hacia la
// luz, caída suave hacia el borde y un halo tenue por fuera. El muestreo es
// 3x3 por píxel porque a 16 px un borde escalonado se nota mucho más que
// cualquier otro detalle.
func Dibujar(tamano int, estado string) image.Image {
	p, ok := paletas[estado]
	if !ok {
		p = paletas["idle"]
	}
	img := image.NewNRGBA(image.Rect(0, 0, tamano, tamano))
	t := float64(tamano)
	cx, cy := t/2, t/2
	radio := t * 0.44         // deja aire para el halo
	luzX, luzY := -0.34, -0.4 // arriba a la izquierda, como en el widget

	const m = 3 // submuestras por eje
	for y := 0; y < tamano; y++ {
		for x := 0; x < tamano; x++ {
			var rr, gg, bb, aa float64
			for sy := 0; sy < m; sy++ {
				for sx := 0; sx < m; sx++ {
					px := float64(x) + (float64(sx)+0.5)/m
					py := float64(y) + (float64(sy)+0.5)/m
					c := muestraOrbe((px-cx)/radio, (py-cy)/radio, p, luzX, luzY)
					a := float64(c.A) / 255
					rr += float64(c.R) * a
					gg += float64(c.G) * a
					bb += float64(c.B) * a
					aa += a
				}
			}
			if aa == 0 {
				continue
			}
			img.SetNRGBA(x, y, color.NRGBA{
				R: uint8(rr / aa),
				G: uint8(gg / aa),
				B: uint8(bb / aa),
				A: uint8(aa / (m * m) * 255),
			})
		}
	}
	return img
}

// muestraOrbe evalúa el color en coordenadas normalizadas donde el radio de
// la esfera es 1.
func muestraOrbe(nx, ny float64, p paleta, luzX, luzY float64) color.NRGBA {
	d := math.Hypot(nx, ny)

	// Halo: fuera de la esfera queda un resplandor que se apaga rápido. Es lo
	// que hace que el orbe parezca emitir luz en vez de estar recortado.
	if d > 1 {
		halo := clamp01((1.25 - d) / 0.25)
		if halo <= 0 {
			return color.NRGBA{}
		}
		c := p.borde
		c.A = uint8(halo * halo * 70)
		return c
	}

	// Distancia al punto de luz: manda el degradado del núcleo al borde.
	dl := clamp01(math.Hypot(nx-luzX, ny-luzY) / 1.55)
	c := mezclar(p.chispa, p.nucleo, math.Pow(dl, 0.75))
	c = mezclar(c, p.borde, math.Pow(clamp01(d), 1.7))

	// Realce del limbo: un anillo tenue justo por dentro del borde, que es lo
	// que da la sensación de volumen esférico.
	if limbo := clamp01((d - 0.72) / 0.28); limbo > 0 {
		c = mezclar(c, p.chispa, limbo*limbo*0.22)
	}

	// Borde suavizado contra el fondo.
	c.A = uint8(clamp01((1-d)/0.06) * 255)
	return c
}

func mezclar(a, b color.NRGBA, t float64) color.NRGBA {
	t = clamp01(t)
	return color.NRGBA{
		R: uint8(float64(a.R)*(1-t) + float64(b.R)*t),
		G: uint8(float64(a.G)*(1-t) + float64(b.G)*t),
		B: uint8(float64(a.B)*(1-t) + float64(b.B)*t),
		A: 0xFF,
	}
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// construirICO empaqueta varios tamaños en un .ico con imágenes PNG dentro,
// que es lo que Windows espera desde Vista. Hacen falta todos los tamaños:
// Windows elige el más cercano y, si sólo hay uno grande, la barra de tareas
// lo reescala y el orbe pierde el borde limpio.
func ConstruirICO(tamanos []int, estado string) ([]byte, error) {
	type entrada struct {
		tamano int
		png    []byte
	}
	imgs := make([]entrada, 0, len(tamanos))
	for _, s := range tamanos {
		var buf bytes.Buffer
		if err := png.Encode(&buf, Dibujar(s, estado)); err != nil {
			return nil, err
		}
		imgs = append(imgs, entrada{s, buf.Bytes()})
	}

	var out bytes.Buffer
	// ICONDIR: reservado, tipo 1 (icono), número de imágenes.
	binary.Write(&out, binary.LittleEndian, uint16(0))
	binary.Write(&out, binary.LittleEndian, uint16(1))
	binary.Write(&out, binary.LittleEndian, uint16(len(imgs)))

	desplazamiento := 6 + 16*len(imgs)
	for _, e := range imgs {
		ancho := byte(e.tamano)
		if e.tamano >= 256 {
			ancho = 0 // 0 significa 256 en el formato
		}
		out.WriteByte(ancho)                                            // ancho
		out.WriteByte(ancho)                                            // alto
		out.WriteByte(0)                                                // colores de paleta (0 = sin paleta)
		out.WriteByte(0)                                                // reservado
		binary.Write(&out, binary.LittleEndian, uint16(1))              // planos
		binary.Write(&out, binary.LittleEndian, uint16(32))             // bits por píxel
		binary.Write(&out, binary.LittleEndian, uint32(len(e.png)))     // tamaño
		binary.Write(&out, binary.LittleEndian, uint32(desplazamiento)) // offset
		desplazamiento += len(e.png)
	}
	for _, e := range imgs {
		out.Write(e.png)
	}
	return out.Bytes(), nil
}
