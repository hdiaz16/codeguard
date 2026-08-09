package internal

import "os"

func DemoRadar() {
	f, err := os.Create("x")
	if err != nil {
		return
	}
	_ = f.Close()
}
