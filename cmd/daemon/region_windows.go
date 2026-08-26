//go:build windows

package main

import (
	"log"
	"sync"
	"syscall"
	"unsafe"
)

// Recorta las ventanas transparentes a su contenido visible, para que el aire
// que las rodea deje de tragarse los clics.
//
// El problema: el widget del orbe es una ventana de 300x180 de la que sólo se
// ven 84 px de orbe; el resto es transparente para que la burbuja quepa. El
// panel es de 480 de ancho y su contenido crece hacia ARRIBA desde el orbe, así
// que con pocos hallazgos la mitad superior está vacía. Pero transparente no es
// inexistente: esas zonas siguen siendo ventana, están siempre encima, y se
// comen cada clic que reciben. El usuario ve un trozo de su pantalla
// inseleccionable sin nada visible que lo explique.
//
// Lo que NO se puede usar: IgnoreMouseEvents. En Windows, Wails lo implementa
// con WS_EX_LAYERED + WS_EX_TRANSPARENT, y una ventana layered deja de
// componerse con transparencia real: el orbe se vuelve un rectángulo blanco
// opaco. Se probó y se revirtió; el aviso vive junto al bloque Windows de
// construirBurbuja.
//
// Lo que sí: SetWindowRgn. Cambia la FORMA de la ventana a nivel del sistema —
// lo de fuera de la región no se dibuja y, lo que importa aquí, tampoco recibe
// ratón: los clics caen en lo que haya debajo. No usa capas, así que la
// transparencia del WebView2 queda intacta.
//
// La forma la dicta la propia página, que es la única que sabe dónde acabó su
// contenido: mide su caja y la manda por un evento. Aquí sólo se traduce a
// píxeles físicos y se aplica.

var (
	user32                 = syscall.NewLazyDLL("user32.dll")
	gdi32                  = syscall.NewLazyDLL("gdi32.dll")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procEnumWindows        = user32.NewProc("EnumWindows")
	procGetWindowTextW     = user32.NewProc("GetWindowTextW")
	procGetWindowThreadPID = user32.NewProc("GetWindowThreadProcessId")
	procIsWindow           = user32.NewProc("IsWindow")
	procSetWindowRgn       = user32.NewProc("SetWindowRgn")
	procCreateRoundRect    = gdi32.NewProc("CreateRoundRectRgn")
	procCreateRectRgn      = gdi32.NewProc("CreateRectRgn")
	procCombineRgn         = gdi32.NewProc("CombineRgn")
	procDeleteObject       = gdi32.NewProc("DeleteObject")
	procGetCurrentPID      = kernel32.NewProc("GetCurrentProcessId")
)

// Rect es una zona activa en píxeles físicos, relativa a la ventana.
type Rect struct{ X, Y, W, H, Radio int }

var (
	hwndMu    sync.Mutex
	hwndCache = map[string]uintptr{}
)

// buscarVentana localiza por título una ventana de ESTE proceso. Wails v3
// beta.5 no expone el handle nativo, así que se enumera y se filtra por PID —
// filtrar sólo por título cogería la ventana de otra aplicación que se llame
// igual.
func buscarVentana(titulo string) uintptr {
	hwndMu.Lock()
	defer hwndMu.Unlock()
	pidPropio, _, _ := procGetCurrentPID.Call()
	if h, ok := hwndCache[titulo]; ok && h != 0 {
		// Windows REUTILIZA los HWND: un handle cacheado puede seguir vivo y
		// pertenecer ya a otra ventana, incluso de otro proceso — y entonces se
		// le recortaría la forma a una ventana ajena. Por eso la validación va
		// AQUÍ y no en un invalidador aparte: se comprueba que existe
		// (IsWindow) y que sigue siendo de ESTE proceso, el mismo filtro que
		// aplica la enumeración de abajo. Eso cubre por igual la ventana
		// recreada y la cerrada de golpe, sin depender de que alguien se
		// acuerde de avisar.
		if r, _, _ := procIsWindow.Call(h); r != 0 {
			var pid uint32
			procGetWindowThreadPID.Call(h, uintptr(unsafe.Pointer(&pid)))
			if uintptr(pid) == pidPropio {
				return h
			}
		}
		delete(hwndCache, titulo)
	}
	// UTF16FromString y no StringToUTF16: la segunda está obsoleta desde Go 1.1
	// porque entra en pánico si la cadena trae un NUL, y aquí el título viene
	// de la configuración de la ventana. Devolver el error es lo correcto.
	objetivo, err := syscall.UTF16FromString(titulo)
	if err != nil {
		return 0
	}
	var encontrada uintptr

	cb := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var pid uint32
		procGetWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if uintptr(pid) != pidPropio {
			return 1 // sigue enumerando
		}
		buf := make([]uint16, 256)
		n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if int(n) != len(objetivo)-1 {
			return 1
		}
		for i := 0; i < int(n); i++ {
			if buf[i] != objetivo[i] {
				return 1
			}
		}
		encontrada = hwnd
		return 0 // encontrada: detener
	})
	procEnumWindows.Call(cb, 0)
	if encontrada != 0 {
		hwndCache[titulo] = encontrada
	}
	return encontrada
}

// RecortarA da a la ventana la forma de las zonas dadas. Sin zonas no hace
// nada: una región vacía escondería la ventana entera, y prefiero un clic
// perdido a un orbe invisible.
func RecortarA(titulo string, zonas []Rect) {
	if len(zonas) == 0 {
		return
	}
	hwnd := buscarVentana(titulo)
	if hwnd == 0 {
		log.Printf("recorte: no encuentro la ventana %q (los clics seguirán cayendo en el aire)", titulo)
		return
	}
	var total uintptr
	for _, z := range zonas {
		if z.W <= 0 || z.H <= 0 {
			continue
		}
		var r uintptr
		if z.Radio > 0 {
			r, _, _ = procCreateRoundRect.Call(
				uintptr(z.X), uintptr(z.Y), uintptr(z.X+z.W), uintptr(z.Y+z.H),
				uintptr(z.Radio*2), uintptr(z.Radio*2))
		} else {
			r, _, _ = procCreateRectRgn.Call(
				uintptr(z.X), uintptr(z.Y), uintptr(z.X+z.W), uintptr(z.Y+z.H))
		}
		if r == 0 {
			continue
		}
		if total == 0 {
			total = r
			continue
		}
		// RGN_OR = 2: la forma final es la unión de todas las zonas.
		destino, _, _ := procCreateRectRgn.Call(0, 0, 1, 1)
		if destino == 0 {
			procDeleteObject.Call(r)
			continue
		}
		// CombineRgn devuelve el tipo de región resultante: 0 es error y 1 es
		// NULLREGION (imposible aquí: la unión de dos zonas no vacías nunca es
		// vacía). En ambos casos «destino» sigue siendo el rectángulo de 1x1 con
		// el que se creó, y sustituir «total» por él dejaría la ventana recortada
		// a un píxel — el orbe invisible que esta función existe para evitar. Se
		// conserva el «total» acumulado hasta ahora.
		if res, _, _ := procCombineRgn.Call(destino, total, r, 2); res <= 1 {
			log.Printf("recorte: CombineRgn falló (resultado %d); se conserva la región anterior", res)
			procDeleteObject.Call(destino)
			procDeleteObject.Call(r)
			continue
		}
		procDeleteObject.Call(total)
		procDeleteObject.Call(r)
		total = destino
	}
	if total == 0 {
		return
	}
	// SetWindowRgn se queda con la propiedad de la región SÓLO si tiene éxito.
	// Si falla (la ventana se cerró entre buscarVentana y aquí), la región sigue
	// siendo de este proceso y hay que liberarla: RecortarA se llama en cada
	// medición de la página, así que cada fallo fugaría un objeto GDI.
	if r, _, _ := procSetWindowRgn.Call(hwnd, total, 1); r == 0 {
		procDeleteObject.Call(total)
		log.Printf("recorte: SetWindowRgn falló para %q (la ventana pudo cerrarse); región liberada", titulo)
	}
}

