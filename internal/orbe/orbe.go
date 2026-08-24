package orbe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"sync"
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

// El cache guarda los PNG ya codificados, que es lo caro: dibujar un orbe de
// 256 px cuesta ~60 ms. Va con su propio candado porque PNG se llama desde
// varias goroutines a la vez —los callbacks de IPC, los temporizadores y el
// menú de la bandeja piden el ícono cada quien por su lado—, y la exclusión
// mutua le toca al paquete que es dueño del estado, no a quien lo usa.
var (
	cacheMu sync.RWMutex
	cache   = map[string][]byte{}
)

// maxEntradasCache acota la MEMORIA del cache. Acotar el tamaño limitó el
// espacio de claves, pero ese espacio sigue siendo grande (tamanoMaximo tamaños
// × estados) y cada PNG pesa cientos de KB: sin tope de entradas, un flujo de
// tamaños variables por el IPC infla el proceso de forma monótona. Los usos
// reales son un puñado de tamaños de bandeja, así que 64 sobra.
const maxEntradasCache = 64

// clave identifica una entrada del cache. Se construye con Sprintf y no
// concatenando string(rune(tamano)): esa conversión no distingue tamaños
// —cualquiera que no sea un punto de código válido acaba en U+FFFD, así que
// dos tamaños distintos compartían entrada— y de paso metía caracteres de
// control en la clave.
func clave(tamano int, estado string) string {
	return fmt.Sprintf("%s:%d", estado, tamano)
}

// tamanoMaximo acota defensivamente el lado de la imagen: la asignación crece
// con tamano²*4 bytes y el muestreo 3x3 con tamano² de CPU, así que un tamaño
// absurdo tumbaría el proceso por memoria. Los íconos reales llegan a 256;
// 1024 deja holgura para cualquier uso legítimo futuro y corta cualquier
// disparate muy por debajo de un OOM (1024²*4 ≈ 4 MB). Es robustez de la
// primitiva, no respuesta a un vector confirmado: hoy los llamadores usan
// constantes, pero el invariante es de la función, no de quien la llama.
const tamanoMaximo = 1024

// acotarTamano clampa el tamaño pedido al rango dibujable [1, tamanoMaximo].
// Es clamp y no error ni panic porque el ícono es decorativo: la función debe
// seguir devolviendo algo dibujable aunque le pidan un tamaño sin sentido.
func acotarTamano(tamano int) int {
	if tamano < 1 {
		return 1
	}
	if tamano > tamanoMaximo {
		return tamanoMaximo
	}
	return tamano
}

// tamanoMaximoICO es el techo del FORMATO .ico: ancho y alto se declaran en un
// solo byte, donde 0 significa 256, así que nada por encima de 256 se puede
// declarar. Es más estricto que tamanoMaximo porque aquí el límite no lo pone la
// memoria sino el formato.
const tamanoMaximoICO = 256

// acotarTamanoICO clampa a lo representable en un .ico. Clamp y no error por lo
// mismo que acotarTamano: el ícono es decorativo. Lo inaceptable no es pedir 512,
// es declarar en la cabecera un tamaño distinto del que se dibujó — con el clamp
// general a 1024, byte(300) da 44 y byte(512) da 0, y Windows se encuentra un
// ícono que no cuadra con su propia cabecera.
func acotarTamanoICO(tamano int) int {
	if t := acotarTamano(tamano); t <= tamanoMaximoICO {
		return t
	}
	return tamanoMaximoICO
}

// PNG devuelve el orbe del estado pedido, al tamaño pedido, ya codificado.
// Es seguro llamarlo desde varias goroutines a la vez. El slice que devuelve
// es el del cache y lo comparten todos los llamadores: hay que tratarlo como
// de sólo lectura.
func PNG(tamano int, estado string) []byte {
	// Se acota ANTES de construir la clave: la clave debe reflejar el tamaño
	// efectivo, no el pedido. Si no, PNG(50000) y PNG(60000) dibujarían lo
	// mismo (ambos clampean a tamanoMaximo) pero ocuparían dos entradas del
	// cache, y peor: una clave pedida podría no corresponder al contenido.
	tamano = acotarTamano(tamano)
	k := clave(tamano, estado)

	cacheMu.RLock()
	b, ok := cache[k]
	cacheMu.RUnlock()
	if ok {
		return b
	}

	// Dibujar y codificar quedan fuera del candado a propósito: son puros y
	// caros, y hacerlos con el lock tomado dejaría esperando a todo el que
	// pida cualquier otro ícono. El precio es que dos goroutines pueden
	// dibujar la misma clave a la vez la primera vez; sale más barato que
	// serializar.
	var buf bytes.Buffer
	_ = png.Encode(&buf, Dibujar(tamano, estado)) // a un bytes.Buffer no falla
	nuevo := buf.Bytes()

	cacheMu.Lock()
	defer cacheMu.Unlock()
	// Doble comprobación: mientras dibujábamos, otra goroutine pudo haber
	// llenado esta misma clave. Nos quedamos con la suya para que todos los
	// llamadores compartan un único slice por clave.
	if b, ok := cache[k]; ok {
		return b
	}
	// Cache lleno: se devuelve el PNG recién dibujado pero NO se guarda. Se
	// prefiere «servir sin guardar» a vaciar el cache, para que un flujo de
	// tamaños raros no expulse las entradas legítimas ya calientes: lo único que
	// paga es el redibujado, que es caro pero correcto y visible en CPU.
	if len(cache) >= maxEntradasCache {
		return nuevo
	}
	cache[k] = nuevo
	return nuevo
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
	// El clamp vive aquí, donde nace la imagen, para que TODOS los caminos
	// queden cubiertos por construcción: PNG, los llamadores directos como
	// genicono y ConstruirICO pasan por este punto.
	tamano = acotarTamano(tamano)
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
		// Se acota aquí también, no sólo dentro de Dibujar: la cabecera del
		// .ico declara el tamaño de cada imagen y debe coincidir con lo que
		// realmente se dibujó, no con lo que se pidió. Y se acota al límite del
		// FORMATO, no al de memoria: con el clamp general a 1024, un 300 acabaría
		// declarando byte(300)=44 sobre un PNG de 300.
		s = acotarTamanoICO(s)
		var buf bytes.Buffer
		if err := png.Encode(&buf, Dibujar(s, estado)); err != nil {
			return nil, err
		}
		imgs = append(imgs, entrada{s, buf.Bytes()})
	}

	var out bytes.Buffer
	// ICONDIR: reservado, tipo 1 (icono), número de imágenes.
	_ = binary.Write(&out, binary.LittleEndian, uint16(0))
	_ = binary.Write(&out, binary.LittleEndian, uint16(1))
	_ = binary.Write(&out, binary.LittleEndian, uint16(len(imgs)))

	desplazamiento := 6 + 16*len(imgs)
	for _, e := range imgs {
		ancho := byte(e.tamano)
		if e.tamano >= 256 {
			ancho = 0 // 0 significa 256 en el formato
		}
		// Todo va a un bytes.Buffer, que nunca falla al escribir.
		out.WriteByte(ancho)                                                // ancho
		out.WriteByte(ancho)                                                // alto
		out.WriteByte(0)                                                    // colores de paleta (0 = sin paleta)
		out.WriteByte(0)                                                    // reservado
		_ = binary.Write(&out, binary.LittleEndian, uint16(1))              // planos
		_ = binary.Write(&out, binary.LittleEndian, uint16(32))             // bits por píxel
		_ = binary.Write(&out, binary.LittleEndian, uint32(len(e.png)))     // tamaño
		_ = binary.Write(&out, binary.LittleEndian, uint32(desplazamiento)) // offset
		desplazamiento += len(e.png)
	}
	for _, e := range imgs {
		out.Write(e.png)
	}
	return out.Bytes(), nil
}
