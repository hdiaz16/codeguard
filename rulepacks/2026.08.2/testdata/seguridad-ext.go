// Fixture de semgrep --test — no es código del producto.
// Casos positivos (ruleid) y negativos (ok) para las reglas go-* de
// seguridad-ext.yaml. Solo necesita parsear: el toolchain de Go ignora
// el directorio testdata.
package fixtures

func inyeccionComandos(entrada string) {
	// ruleid: go-command-injection
	exec.Command("sh", "-c", entrada)
	// ruleid: go-command-injection
	exec.Command(fmt.Sprintf("/usr/bin/%s", entrada))
	// ok: go-command-injection
	exec.Command("git", "status")
}

func jwtSinVerificar(analizador *jwt.Parser, cadena string, funcionClave jwt.Keyfunc) {
	// ruleid: go-jwt-no-verify
	analizador.ParseUnverified(cadena, jwt.MapClaims{})
	// ok: go-jwt-no-verify
	analizador.Parse(cadena, funcionClave)
}

func criptografia(datos []byte) {
	// ruleid: go-crypto-debil
	md5.New()
	// ruleid: go-crypto-debil
	sha1.Sum(datos)
	// ok: go-crypto-debil
	sha256.Sum256(datos)
}

func aleatorios() {
	// ruleid: go-random-inseguro
	tokenSesion := rand.Intn(999999)
	// ok: go-random-inseguro
	espera := rand.Intn(100)
	usar(tokenSesion, espera)
}

func configuracionTLS() {
	// ruleid: go-tls-verify-off
	confInsegura := &tls.Config{InsecureSkipVerify: true}
	// ok: go-tls-verify-off
	confSegura := &tls.Config{MinVersion: tls.VersionTLS12}
	usar(confInsegura, confSegura)
}

func extraer(destino string, entrada *zip.File) {
	// ruleid: go-zip-slip
	ruta := filepath.Join(destino, entrada.Name)
	// ok: go-zip-slip
	rutaManifiesto := filepath.Join(destino, "manifiesto.json")
	usar(ruta, rutaManifiesto)
}

func usar(valores ...interface{}) {}
