//go:build windows

package secreto

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// El ciclo completo contra la bóveda de VERDAD, no contra un doble.
//
// Un almacén de secretos es exactamente la clase de cosa donde una
// implementación que "compila y no da error" puede no guardar nada: las
// llamadas a Win32 devuelven un booleano, y si la estructura CREDENTIALW está
// mal alineada, Windows escribe algo distinto de lo que creemos sin quejarse.
// La única forma de saberlo es escribir, leer y comparar.
func TestGuardarLeerBorrar(t *testing.T) {
	const variable = "CODEGUARD_PRUEBA_NO_USAR"
	// Largo y con no-ASCII, pero dentro del tope: el motivo de no usar `setx`
	// era su límite de 1024, así que la bóveda tiene que aguantar más que eso.
	// Se mide en BYTES, no en runes: áéñ ocupan dos cada una.
	valor := strings.Repeat("clave-áéñ-1234567890-", 80)
	if len(valor) <= 1024 {
		t.Fatalf("el valor de prueba (%d bytes) no supera el límite de setx; "+
			"así no prueba lo que se quiere probar", len(valor))
	}

	t.Cleanup(func() { _ = Borrar(variable) })

	if err := Guardar(variable, valor); err != nil {
		t.Fatalf("Guardar: %v", err)
	}
	got, err := Leer(variable)
	if err != nil {
		t.Fatalf("Leer: %v", err)
	}
	if got != valor {
		t.Fatalf("lo leído no es lo guardado: %d bytes vs %d", len(got), len(valor))
	}

	// Sobrescribir tiene que reemplazar, no acumular ni fallar: cambiar de
	// clave es lo más normal del mundo.
	if err := Guardar(variable, "otra"); err != nil {
		t.Fatalf("sobrescribir: %v", err)
	}
	if got, _ := Leer(variable); got != "otra" {
		t.Errorf("tras sobrescribir salió %q", got)
	}

	if err := Borrar(variable); err != nil {
		t.Fatalf("Borrar: %v", err)
	}
	if _, err := Leer(variable); !NoEncontrado(err) {
		t.Errorf("tras borrar debería ser 'no encontrado', fue %v", err)
	}
	// Borrar dos veces no puede reventar: la migración lo hace sin comprobar.
	if err := Borrar(variable); err != nil {
		t.Errorf("borrar de nuevo dio error: %v", err)
	}
}

// Una clave desmedida tiene que dar un error que se entienda. Windows contesta
// "The stub received bad data", que es LO MISMO que dice una estructura mal
// formada: sin este mensaje, quien pegue de más se pasa la tarde buscando un
// bug de alineación que no existe.
func TestUnaClaveDemasiadoGrandeLoDiceClaro(t *testing.T) {
	const variable = "CODEGUARD_PRUEBA_GRANDE"
	t.Cleanup(func() { _ = Borrar(variable) })
	err := Guardar(variable, strings.Repeat("a", maxBlob+1))
	if err == nil {
		t.Fatal("aceptó una clave por encima del tope")
	}
	if !strings.Contains(err.Error(), "Administrador de credenciales") {
		t.Errorf("el error no explica el motivo: %v", err)
	}
}

func TestLeerLoQueNoExisteSeDistingueDeUnFallo(t *testing.T) {
	if _, err := Leer("CODEGUARD_ESTA_NO_EXISTE_JAMAS"); !NoEncontrado(err) {
		t.Fatalf("esperaba 'no encontrado' y fue %v; sin esa distinción, "+
			"una bóveda averiada se confunde con una vacía y se cae al registro en silencio", err)
	}
}

// La prueba que justifica el cambio entero: lo guardado NO puede quedar
// también en el entorno del usuario, que es de donde lo lee cualquier proceso.
func TestElSecretoNoAcabaEnElEntorno(t *testing.T) {
	const variable = "CODEGUARD_PRUEBA_ENTORNO"
	const valor = "no-debo-aparecer-en-el-entorno"
	t.Cleanup(func() { _ = Borrar(variable) })

	if err := Guardar(variable, valor); err != nil {
		t.Fatalf("Guardar: %v", err)
	}
	if v := os.Getenv(variable); v != "" {
		t.Errorf("la clave apareció en el entorno del proceso: %q", v)
	}
	for _, e := range os.Environ() {
		if strings.Contains(e, valor) {
			t.Fatalf("el valor se filtró al entorno: %q", e)
		}
	}
	exigirQueNoEsteEnElEntornoPersistente(t, variable)
}

// exigirQueNoEsteEnElEntornoPersistente mira HKCU\Environment, que es DONDE VIVE
// el entorno del usuario.
//
// Es la comprobación que le faltaba a la prueba y sin la cual no probaba lo que
// dice. os.Getenv y os.Environ sólo enseñan el entorno de ESTE proceso, y una
// implementación que persistiera la clave al estilo `setx` escribe en el
// registro sin tocar el proceso en curso: la variable no aparecería por ninguna
// de las dos vías y la prueba habría dado por bueno exactamente el fallo que
// dice descartar. El daño de ese fallo es que la clave queda legible para
// cualquier proceso del usuario y sobrevive a la desinstalación.
//
// Se leen los NOMBRES de los valores en vez de pedir el valor con
// GetStringValue a propósito: GetStringValue devuelve ErrUnexpectedType si el
// dato es REG_EXPAND_SZ —que es como Windows guarda buena parte de las variables
// de usuario—, así que preguntar por el valor podría dar "no está" teniéndolo
// delante.
func exigirQueNoEsteEnElEntornoPersistente(t *testing.T, variable string) {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("no se pudo abrir HKCU\\Environment, así que la prueba NO comprobó "+
			"lo que dice comprobar: %v", err)
	}
	defer k.Close()

	nombres, err := k.ReadValueNames(0)
	if err != nil {
		t.Fatalf("no se pudieron leer los valores de HKCU\\Environment: %v", err)
	}
	for _, n := range nombres {
		if strings.EqualFold(n, variable) {
			t.Errorf("la clave quedó en el ENTORNO PERSISTENTE del usuario "+
				"(HKCU\\Environment\\%s). Ahí la lee cualquier proceso que arranque "+
				"después y sobrevive a la desinstalación: es justo lo que la bóveda "+
				"existe para evitar.", n)
		}
	}
}
