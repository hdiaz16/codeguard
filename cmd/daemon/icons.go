package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Íconos del tray generados en runtime: un círculo de color por estado
// (§12.1). Sin assets externos, sin dependencias.

var stateColors = map[string]color.NRGBA{
	"idle":     {R: 0x6B, G: 0x7D, B: 0x8C, A: 0xFF}, // gris azulado
	"working":  {R: 0xD9, G: 0xA6, B: 0x4A, A: 0xFF}, // ámbar
	"pass":     {R: 0x4C, G: 0xB8, B: 0x6E, A: 0xFF}, // verde
	"blocked":  {R: 0xE0, G: 0x4A, B: 0x3A, A: 0xFF}, // rojo
	"degraded": {R: 0xD9, G: 0x7E, B: 0x4A, A: 0xFF}, // naranja
	"offline":  {R: 0x6B, G: 0x7D, B: 0x8C, A: 0xFF}, // aro gris (sin relleno)
}

var iconCache = map[string][]byte{}

func trayIcon(state string) []byte {
	if b, ok := iconCache[state]; ok {
		return b
	}
	c, ok := stateColors[state]
	if !ok {
		c = stateColors["idle"]
	}
	const size = 32
	cx, cy, r := float64(size)/2, float64(size)/2, 13.0
	img := image.NewNRGBA(image.Rect(0, 0, size, size))

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dist := math.Hypot(float64(x)+0.5-cx, float64(y)+0.5-cy)
			var alpha float64
			if state == "offline" {
				// solo el aro: presente pero sin conexión
				alpha = math.Min(clamp01(r-dist), clamp01(dist-(r-3.5)))
			} else {
				alpha = clamp01(r - dist) // relleno con borde suavizado
			}
			if alpha <= 0 {
				continue
			}
			px := c
			px.A = uint8(alpha * 255)
			img.SetNRGBA(x, y, px)
		}
	}

	// blocked: barra blanca horizontal (señal de prohibido)
	if state == "blocked" {
		for y := 13; y < 19; y++ {
			for x := 8; x < 24; x++ {
				dist := math.Hypot(float64(x)+0.5-cx, float64(y)+0.5-cy)
				if dist < r-1.5 {
					img.SetNRGBA(x, y, color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF})
				}
			}
		}
	}
	// working: punto blanco central (actividad)
	if state == "working" {
		for y := 0; y < size; y++ {
			for x := 0; x < size; x++ {
				if math.Hypot(float64(x)+0.5-cx, float64(y)+0.5-cy) < 4 {
					img.SetNRGBA(x, y, color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF})
				}
			}
		}
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)
	iconCache[state] = buf.Bytes()
	return buf.Bytes()
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
