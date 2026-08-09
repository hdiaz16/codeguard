package main

import "codeguard/internal/orbe"

// El ícono de la bandeja es el mismo orbe que el widget en pantalla: una sola
// identidad visual, dibujada en Go, sin assets externos que se puedan perder.
func trayIcon(estado string) []byte { return orbe.PNG(32, estado) }

// iconoOficial es la identidad de CodeGuard —el orbe en reposo— para la
// ventana, la barra de tareas y el cuadro "acerca de".
func iconoOficial() []byte { return orbe.PNG(256, "idle") }
