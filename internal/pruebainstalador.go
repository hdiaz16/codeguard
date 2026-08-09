package pruebainstalador

import "os"

// Debe disparar la regla que adopte de CodeQL.
func escribir(p string) error {
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString("hola")
	return nil
}
