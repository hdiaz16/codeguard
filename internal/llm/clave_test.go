package llm

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/secreto"
)

// errBovedaRota es un fallo de los que NO son "aquí no hay nada guardado":
// permisos, servicio de credenciales parado, credencial corrupta.
var errBovedaRota = errors.New("el servicio de credenciales no responde")

// REGLA DEL PAQUETE: las pruebas de este archivo reasignan las globales
// leerSecreto y ultimoAviso —el mecanismo de inyección y la memoria del filtro
// anti-repetición de ClaveDe—, y capturarLog reasigna la salida de log, que
// también es global del proceso. Mientras siga así, NINGÚN test de este paquete
// puede usar t.Parallel() ni llamar a ClaveDe desde una goroutine: sería una
// carrera sobre esas variables, con verdes y rojos intermitentes en la prueba
// que no tiene la culpa. El cierre real —pasar la lectora por parámetro en vez
// de mutar una global— vive en clave.go y queda pendiente.

// noEncontradoDeVerdad pide a la bóveda REAL el error de "esto no existe".
//
// Se pide en vez de fabricarlo porque el centinela no es exportable, y sobre
// todo porque un error inventado dejaría la prueba en verde aunque
// secreto.NoEncontrado dejara de reconocerlo — y esa distinción es justo la
// mitad del arreglo. Es una lectura de una credencial inexistente: no escribe
// nada en la bóveda de nadie.
func noEncontradoDeVerdad(t *testing.T) error {
	t.Helper()
	_, err := secreto.Leer("CG_PRUEBA_CREDENCIAL_QUE_NO_EXISTE")
	if err == nil {
		t.Fatal("una credencial inventada no debería existir")
	}
	if !secreto.NoEncontrado(err) {
		t.Fatalf("la bóveda no dio «no encontrado» para algo inexistente: %v", err)
	}
	return err
}

// capturarLog devuelve lo que se escriba en el log durante la prueba.
func capturarLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var salida bytes.Buffer
	log.SetOutput(&salida)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &salida
}

// Un fallo REAL de la bóveda no puede verse igual que «todavía no has guardado
// la clave».
//
// ClaveDe hacía `if v, err := secreto.Leer(...); err == nil && v != ""` y caía
// al entorno con CUALQUIER error. Una bóveda corrupta, sin permisos o con el
// servicio parado terminaba exactamente igual que un repo sin migrar: la capa
// se apagaba diciendo "sin API key", y el dev se iba a configurar una clave que
// ya estaba guardada. La avería se leía como descuido propio.
func TestUnFalloDeLaBovedaNoSeDisfrazaDeClaveAusente(t *testing.T) {
	const variable = "CG_PRUEBA_CLAVE_MODELO"
	noHay := noEncontradoDeVerdad(t)

	casos := []struct {
		nombre    string
		guardada  string
		errBoveda error
		entorno   string
		quiero    string
		avisa     []string // subcadenas que el log DEBE traer; vacío = silencio
	}{
		{
			nombre:   "la bóveda tiene la clave: manda ella y el entorno no se mira",
			guardada: "de-la-boveda", entorno: "del-entorno",
			quiero: "de-la-boveda",
		},
		{
			nombre:    "no hay nada guardado: se cae al entorno, y eso no es noticia",
			errBoveda: noHay, entorno: "del-entorno",
			quiero: "del-entorno",
		},
		{
			nombre:    "bóveda rota con el entorno puesto: la capa sigue, pero se dice",
			errBoveda: errBovedaRota, entorno: "del-entorno",
			quiero: "del-entorno",
			avisa:  []string{variable, "no responde", "GUARDADA"},
		},
		{
			nombre:    "bóveda rota y sin entorno: NO es que falte configurar la clave",
			errBoveda: errBovedaRota,
			quiero:    "",
			avisa:     []string{variable, "FALLO de la bóveda", "no porque falte"},
		},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			original := leerSecreto
			avisoPrevio := ultimoAviso
			leerSecreto = func(string) (string, error) { return c.guardada, c.errBoveda }
			// Se restauran AMBAS globales: dejar ultimoAviso pisado al salir
			// contamina cualquier otra prueba del paquete que dependa del filtro
			// anti-repetición, y el fallo saldría en la que no tiene la culpa.
			t.Cleanup(func() { leerSecreto = original; ultimoAviso = avisoPrevio })
			ultimoAviso = "" // la memoria del filtro anti-repetición, entre casos
			t.Setenv(variable, c.entorno)
			salida := capturarLog(t)

			if got := ClaveDe(config.LLM{APIKeyEnv: variable}); got != c.quiero {
				t.Errorf("ClaveDe devolvió %q, se esperaba %q", got, c.quiero)
			}

			registrado := salida.String()
			if len(c.avisa) == 0 {
				if registrado != "" {
					t.Errorf("este camino no ha fallado y no debe hablar; escribió:\n%s", registrado)
				}
				return
			}
			for _, trozo := range c.avisa {
				if !strings.Contains(registrado, trozo) {
					t.Errorf("el aviso no menciona %q — sin eso, el síntoma sigue siendo "+
						"«no configuraste la clave»:\n%s", trozo, registrado)
				}
			}
		})
	}
}

// El aviso se dice una vez, pero se vuelve a decir si la avería vuelve.
//
// ClaveDe consulta la bóveda en CADA uso —para que una clave recién guardada se
// vea sin reiniciar el daemon— y la pantalla de configuración la llama en cada
// refresco: sin filtro, una bóveda rota escribe la misma línea decenas de veces
// y entierra el resto del log, que es otra manera de no decir nada. Con un
// sync.Once, en cambio, la segunda avería habría sido tan muda como el bug que
// esto viene a quitar.
func TestElAvisoDeBovedaNiInundaElLogNiSeCallaLaSegundaVez(t *testing.T) {
	const variable = "CG_PRUEBA_CLAVE_MODELO"
	original := leerSecreto
	avisoPrevio := ultimoAviso
	t.Cleanup(func() { leerSecreto = original; ultimoAviso = avisoPrevio })
	t.Setenv(variable, "")
	ultimoAviso = ""
	salida := capturarLog(t)

	rota := func(string) (string, error) { return "", errBovedaRota }
	buena := func(string) (string, error) { return "clave-guardada", nil }

	leerSecreto = rota
	for i := 0; i < 5; i++ {
		ClaveDe(config.LLM{APIKeyEnv: variable})
	}
	if n := strings.Count(salida.String(), "no pudo leer"); n != 1 {
		t.Errorf("cinco consultas con la bóveda rota escribieron %d avisos, se esperaba 1:\n%s",
			n, salida.String())
	}

	// La bóveda se arregla (nada que decir), y vuelve a romperse: eso SÍ se
	// cuenta otra vez.
	leerSecreto = buena
	ClaveDe(config.LLM{APIKeyEnv: variable})
	leerSecreto = rota
	ClaveDe(config.LLM{APIKeyEnv: variable})
	if n := strings.Count(salida.String(), "no pudo leer"); n != 2 {
		t.Errorf("la avería reapareció y el log lleva %d avisos, se esperaban 2:\n%s",
			n, salida.String())
	}
}
