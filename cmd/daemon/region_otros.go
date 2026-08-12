//go:build !windows

package main

// Fuera de Windows no hay SetWindowRgn. El recorte de las ventanas
// transparentes es específico de la composición de Windows, y en el resto de
// plataformas el problema —o no existe, o se resuelve con click-through nativo
// que ahí sí funciona sin romper la transparencia.

// Rect es una zona activa en píxeles físicos, relativa a la ventana.
type Rect struct{ X, Y, W, H, Radio int }

func RecortarA(string, []Rect) {}
func OlvidarVentanas()         {}
