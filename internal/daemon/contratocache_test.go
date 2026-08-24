package daemon

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/engines/contrato"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// LA SEGUNDA MITAD DEL CONTRATO, Y LA QUE NADIE HABÍA MEDIDO: EL CACHÉ.
//
// El contrato dice que un motor devuelve hallazgos o el porqué. Pero los motores
// no sólo responden: también GUARDAN, bajo una clave de contenido, para no
// repetir trabajo. Y "analizado y limpio" es, con diferencia, el resultado que
// más veces se reutiliza.
//
// Ahí está el peligro, y es peor que el fallo original. Un motor averiado que
// devolvía (nil, nil) mentía UNA vez, en esa corrida. Si además esa lista vacía
// se guarda bajo el sha del contenido, la mentira se vuelve PERMANENTE: mañana,
// con la herramienta ya arreglada, el motor encuentra la clave, sirve "sin
// hallazgos" y no vuelve a mirar ese contenido nunca. El commit sale en verde y
// no queda ni rastro de la avería que lo causó.
//
// El invariante es corto: **lo que no se pudo analizar no se guarda.**
//
// Se comprueba con los mismos sabotajes del contrato y con un caché espía, así
// que cubre los 17 motores de una vez y el que se añada mañana nace cubierto.
func TestUnMotorAveriadoNoDejaHuellaEnElCache(t *testing.T) {
	raiz := fixtureCacheable(t)
	cfg := conLanguages("go", "python", "sql", "typescript", "csharp", "java")
	cfg.Paths.Migrations = []string{"migrations/*.sql", "migrations/**/*.sql"}
	cfg.Paths.MigrationsDialect = "postgres"

	for _, s := range sabotajes {
		t.Run(s.nombre, func(t *testing.T) {
			espia := &cacheEspia{}
			motores := motoresBajoContrato(cfg, espia)
			in := engines.Input{RepoRoot: raiz, Files: archivosConSHA(t, raiz)}

			for _, motor := range motores {
				if _, exento := exentosDelContrato[motor.Name()]; exento {
					continue
				}
				t.Run(motor.Name(), func(t *testing.T) {
					contrato.OlvidarTodo()
					t.Setenv("PATH", señuelos(t, s)+string(os.PathListSeparator)+os.Getenv("PATH"))

					antes := espia.escrituras()
					_, err := motor.Run(context.Background(), in)
					nuevas := espia.escrituras() - antes

					// El contrato ya exige que esto sea un error; si no lo fuera, el
					// otro test lo dice mejor. Aquí lo que se juzga es la huella.
					if err != nil && nuevas > 0 {
						t.Errorf("%s no pudo analizar (%v) y AUN ASÍ guardó %d entrada(s) en el "+
							"caché.\n\n"+
							"Una lista vacía guardada bajo la clave del contenido convierte una "+
							"avería de hoy en un ✓ verde permanente: en la corrida siguiente el "+
							"motor encuentra la clave, sirve «sin hallazgos» y ya no vuelve a "+
							"mirar ese contenido — con la herramienta arreglada y todo.\n\n"+
							"Lo que no se pudo analizar no se guarda.",
							motor.Name(), err, nuevas)
					}
				})
			}
		})
	}
}

// EL CONTROL, y sin él el test de arriba no vale nada: si NINGÚN motor escribiera
// nunca en el caché —porque el caché no llega, porque Engines lo ignora, porque el
// espía no está enchufado— el invariante se cumpliría solo y no estaría
// comprobando nada.
//
// Con las herramientas de verdad y un fixture que sí se puede analizar, alguien
// tiene que guardar algo. No se exige quién ni cuántos: en esta máquina faltan
// herramientas (el jar de google-java-format no arranca con este JDK) y atar el
// test a una lista concreta lo volvería frágil por el motivo equivocado.
func TestConLasHerramientasDeVerdadElCacheSiSeUsa(t *testing.T) {
	if testing.Short() {
		t.Skip("integración: lanza las herramientas reales sobre el fixture")
	}
	raiz := fixtureCacheable(t)
	cfg := conLanguages("go", "python", "sql", "typescript", "csharp", "java")
	cfg.Paths.Migrations = []string{"migrations/*.sql", "migrations/**/*.sql"}
	cfg.Paths.MigrationsDialect = "postgres"

	espia := &cacheEspia{}
	in := engines.Input{RepoRoot: raiz, Files: archivosConSHA(t, raiz)}
	var quienes []string
	for _, motor := range motoresBajoContrato(cfg, espia) {
		antes := espia.escrituras()
		_, _ = motor.Run(context.Background(), in)
		if espia.escrituras() > antes {
			quienes = append(quienes, motor.Name())
		}
	}
	if len(quienes) == 0 {
		t.Fatal("ni un motor escribió en el caché con las herramientas de verdad, así que " +
			"TestUnMotorAveriadoNoDejaHuellaEnElCache se está cumpliendo por no haber caché " +
			"que ensuciar, no por hacer lo correcto. Comprueba que Engines() reciba el espía.")
	}
	t.Logf("escribieron en el caché: %v", quienes)
}

// fixtureCacheable es el fixture políglota en condiciones de PODER cachearse, y
// existe porque el control de arriba se puso rojo la primera vez.
//
// Sin esto el invariante «lo averiado no se guarda» se cumplía solo, y por dos
// motivos a la vez: los motores de módulo (govet, staticcheck, tsc, dotnet-build)
// sacan su clave de engines.HuellaModulo, que pregunta a `git ls-files` y sin repo
// devuelve vacío —clave vacía, no cacheable—, y los motores por archivo la sacan
// del SHA256 del ChangedFile, que archivosDe deja en blanco. O sea que el caché no
// entraba en juego y el test parecía verde por buen comportamiento cuando lo era
// por falta de oportunidad.
//
// `git add` basta: `ls-files` cuenta lo que está en el índice, sin necesidad de
// commit ni de identidad configurada.
func fixtureCacheable(t *testing.T) string {
	t.Helper()
	raiz := fixturePoliglota(t)
	for _, args := range [][]string{{"init"}, {"add", "-A"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = raiz
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("sin git no se puede ejercitar el caché (%v): %s", err, out)
		}
	}
	return raiz
}

// archivosConSHA presenta el fixture como un cambio CON la huella de contenido de
// cada archivo, que es lo que el gancho manda de verdad y lo que los motores por
// archivo usan como clave de caché.
func archivosConSHA(t *testing.T, raiz string) []gitdiff.ChangedFile {
	t.Helper()
	out := archivosDe(t, raiz)
	for i := range out {
		out[i].SHA256 = gitdiff.SHA256De(raiz, out[i].Path)
	}
	return out
}

// cacheEspia cuenta escrituras. No sirve nada al leer a propósito: así cada
// motor analiza de verdad y se ve qué decide guardar.
type cacheEspia struct {
	mu      sync.Mutex
	escrito int
}

func (c *cacheEspia) Leer([]string) map[string][]finding.Finding { return nil }

func (c *cacheEspia) Guardar(entradas []engines.Cacheable) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// El espía respeta la vigencia igual que la implementación real: un fake
	// que la ignore mediría un caché que no existe.
	for _, e := range entradas {
		if e.Vigente != nil && e.Vigente() {
			c.escrito++
		}
	}
}

func (c *cacheEspia) escrituras() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.escrito
}
