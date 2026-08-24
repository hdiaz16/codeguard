package store

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"codeguard/internal/finding"
	"codeguard/internal/pipeline"
)

// La BD la comparten hook, ci y daemon, y el daemon además lanza una goroutine
// por petición: el mismo proceso puede tener varias escrituras encima a la vez
// (SaveRun, FileCachePut, SaveFeedback). SQLite admite UN escritor y punto, así
// que el único sitio donde esas escrituras pueden hacer cola sin pelearse es el
// pool de database/sql.
//
// El test abre con un busy_timeout de 1 ms en lugar de los 5 s de producción.
// No es un truco para forzar el fallo: el busy_timeout es espera-y-reintento
// para arbitrar con OTROS PROCESOS, y aquí la base vive en un directorio
// temporal que nadie más toca. Con él casi anulado, cualquier "database is
// locked" que salga lo ha producido este proceso peleándose consigo mismo —
// que es justo lo que no debe pasar. Con los 5 s de producción el mismo choque
// no desaparece: se convierte en cinco segundos de espera dentro del hook de
// commit, y sólo se ve como error cuando la contención aprieta.
func TestOpen_EscriturasConcurrentesNoDevuelvenBusy(t *testing.T) {
	// El choque ocurre entero en la primera vuelta: al soltar la barrera, 32
	// transacciones de escritura piden la base a la vez. Las vueltas de más no
	// descubren nada nuevo y cada una cuesta tres commits (tres fsync), así que
	// se quedan en dos: suficiente para que el solape también se dé con la
	// cola ya caliente, y barato.
	const escritores = 32
	const iteraciones = 2
	const porLote = 20

	s, err := abrir(filepath.Join(t.TempDir(), "concurrente.db"), 1)
	if err != nil {
		t.Fatalf("abriendo la BD: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	// La aserción estable del contrato: una sola conexión. Sin esto, el resto
	// del test depende de que el sistema de archivos colabore.
	if n := s.db.Stats().MaxOpenConnections; n != 1 {
		t.Errorf("el pool admite %d conexiones abiertas (0 = sin límite) y SQLite sólo admite un escritor:\n"+
			"database/sql tiene que ser quien haga la cola, no el busy_timeout", n)
	}

	repoID := CanonicalRepoID("local/concurrencia")
	if err := s.UpsertRepo(repoID, "", "concurrencia"); err != nil {
		t.Fatal(err)
	}

	// Todos esperan la misma señal: el solape de transacciones de escritura es
	// el fenómeno que se mide, y arrancar en fila lo escondería.
	arranque := make(chan struct{})
	fallos := make(chan error, escritores*iteraciones*3)
	var wg sync.WaitGroup
	for g := 0; g < escritores; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-arranque
			for i := 0; i < iteraciones; i++ {
				f := finding.Finding{
					ID: NewULID(), Engine: "semgrep", RuleKey: "regla-concurrente",
					Pillar: finding.Quality, Severity: finding.Warning, Source: finding.Deterministic,
					File: "a.go", Line: i + 1, Message: "aviso", Fingerprint: NewULID(),
				}
				err := s.SaveRun(RunMeta{
					RunID: NewULID(), RepoID: repoID, Branch: "master",
					RulepackVer: "2026.08.2", ConfigHash: "cfg", Environment: "local",
				}, &pipeline.Result{Verdict: pipeline.Pass, Degraded: []string{},
					Findings: []finding.Finding{f, f2(i), f2(i + 1)}},
					pipeline.Finalizar(&pipeline.Result{Verdict: pipeline.Pass}, "", nil), 3)
				if err != nil {
					fallos <- fmt.Errorf("SaveRun g%d i%d: %w", g, i, err)
					continue // sin run no hay finding: el feedback fallaría por la FK, no por contención
				}

				lote := make(map[string]string, porLote)
				for k := 0; k < porLote; k++ {
					lote[fmt.Sprintf("sha-%d-%d-%d", g, i, k)] = "[]"
				}
				if err := s.FileCachePut(repoID, "2026.08.2", "cfg", lote); err != nil {
					fallos <- fmt.Errorf("FileCachePut g%d i%d: %w", g, i, err)
				}
				if err := s.SaveFeedback(f.ID, "useful", ""); err != nil {
					fallos <- fmt.Errorf("SaveFeedback g%d i%d: %w", g, i, err)
				}
			}
		}(g)
	}
	close(arranque)
	wg.Wait()
	close(fallos)

	n, bloqueos := 0, 0
	for err := range fallos {
		n++
		if esBusy(err) {
			bloqueos++
		}
		if n <= 5 { // una muestra basta; el conteo dice el resto
			t.Errorf("escritura concurrente fallida: %v", err)
		}
	}
	if n > 0 {
		t.Fatalf("%d de %d escrituras fallaron (%d por bloqueo de la base).\n"+
			"Con la BD en un temporal no hay otro proceso: el proceso se está "+
			"bloqueando a sí mismo porque el pool abre varias conexiones contra "+
			"un motor de un solo escritor.", n, escritores*iteraciones*3, bloqueos)
	}
}

// El precio de tener UNA sola conexión es que un recorrido de filas abierto la
// retiene entera: si alguien consultara la base DENTRO del bucle de un
// *sql.Rows, se esperaría a sí mismo para siempre — un cuelgue, no un error, y
// sin traza. Hoy ningún método hace eso (ExportarRuns es el que más rato tiene
// filas abiertas, y lo que hace dentro del bucle es escribir el CSV, no
// consultar). Este test cruza los recorridos largos con escrituras para que, si
// alguien mete una consulta dentro de uno de esos bucles, salga aquí como un
// fallo con nombre y no como un daemon congelado en producción.
func TestUnaSolaConexionNoSeAutobloquea(t *testing.T) {
	s := bd(t)
	repoID := CanonicalRepoID("local/autobloqueo")
	if err := s.UpsertRepo(repoID, "", "autobloqueo"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		f := finding.Finding{
			ID: NewULID(), Engine: "semgrep", RuleKey: "r", Pillar: finding.Quality,
			Severity: finding.Warning, Source: finding.Deterministic,
			File: "a.go", Line: i, Message: "m", Fingerprint: NewULID(),
		}
		guardarRun(t, s, NewULID(), repoID, "block", []finding.Finding{f})
		if err := s.SaveFeedback(f.ID, "false_positive", ""); err != nil {
			t.Fatal(err)
		}
	}

	dir := t.TempDir()
	listo := make(chan error, 6)
	tareas := []func(i int) error{
		func(i int) error {
			_, err := s.ExportarRuns(filepath.Join(dir, fmt.Sprintf("e%d.csv", i)), FiltroExport{Repo: repoID})
			return err
		},
		func(int) error { _, err := s.ResumenSemanal(repoID); return err },
		func(int) error { _, err := s.RuleStats(repoID); return err },
		func(int) error { _, err := s.Emisiones(repoID); return err },
		func(int) error { _, err := s.ProgresoCalibracion(repoID); return err },
		func(i int) error {
			return s.FileCachePut(repoID, "2026.08.2", "cfg", map[string]string{fmt.Sprintf("s%d", i): "[]"})
		},
	}
	for n, tarea := range tareas {
		go func(n int, tarea func(int) error) {
			for i := 0; i < 10; i++ {
				if err := tarea(n*100 + i); err != nil {
					listo <- fmt.Errorf("tarea %d: %w", n, err)
					return
				}
			}
			listo <- nil
		}(n, tarea)
	}

	// Un auto-bloqueo no devuelve error: se queda quieto. El plazo es lo único
	// que lo convierte en un fallo legible.
	plazo := time.After(60 * time.Second)
	for range tareas {
		select {
		case err := <-listo:
			if err != nil {
				t.Fatal(err)
			}
		case <-plazo:
			t.Fatal("con una sola conexión, alguna operación se quedó esperándose a sí misma:\n" +
				"busca una consulta o una escritura hecha DENTRO del bucle de un *sql.Rows, " +
				"o una transacción que no se cierra en todos los caminos")
		}
	}
}

// f2 arma hallazgos de relleno para que cada SaveRun sea una transacción de
// varias sentencias: una transacción de una sola sentencia casi no solapa.
func f2(i int) finding.Finding {
	return finding.Finding{
		ID: NewULID(), Engine: "semgrep", RuleKey: "relleno",
		Pillar: finding.Quality, Severity: finding.Info, Source: finding.Deterministic,
		File: "b.go", Line: i + 1, Message: "relleno", Fingerprint: NewULID(),
	}
}

// esBusy distingue el bloqueo de la base de cualquier otro error: si el test
// falla, importa saber si falló por contención o por otra cosa.
func esBusy(err error) bool {
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "locked") || strings.Contains(m, "busy")
}

// BenchmarkLecturas mide el coste del pool de una conexión sobre las lecturas,
// que es lo que se paga por quitar la contención de escritura: en WAL varios
// lectores podrían ir en paralelo y con una conexión hacen cola. Está aquí para
// que la próxima persona que quiera subir el tope traiga números, no
// intuiciones.
func BenchmarkLecturas(b *testing.B) {
	s, err := abrir(filepath.Join(b.TempDir(), "lecturas.db"), 5000)
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	repoID := CanonicalRepoID("local/bench")
	if err := s.UpsertRepo(repoID, "", "bench"); err != nil {
		b.Fatal(err)
	}
	var shas []string
	lote := map[string]string{}
	for i := 0; i < 500; i++ {
		sha := fmt.Sprintf("sha-%04d", i)
		shas = append(shas, sha)
		lote[sha] = "[]"
	}
	if err := s.FileCachePut(repoID, "2026.08.2", "cfg", lote); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		f := finding.Finding{
			ID: NewULID(), Engine: "semgrep", RuleKey: "r", Pillar: finding.Quality,
			Severity: finding.Warning, Source: finding.Deterministic,
			File: "a.go", Line: i, Message: "m", Fingerprint: NewULID(),
		}
		runID := NewULID()
		if err := s.SaveRun(RunMeta{RunID: runID, RepoID: repoID, Branch: "master",
			RulepackVer: "2026.08.2", ConfigHash: "cfg", Environment: "local"},
			&pipeline.Result{Verdict: pipeline.Pass, Degraded: []string{},
				Findings: []finding.Finding{f}},
			pipeline.Finalizar(&pipeline.Result{Verdict: pipeline.Pass}, "", nil), 1); err != nil {
			b.Fatal(err)
		}
		if err := s.SaveFeedback(f.ID, "useful", ""); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := s.FileCacheGet(repoID, "2026.08.2", "cfg", shas); err != nil {
				b.Error(err)
				return
			}
			if _, err := s.RuleStats(repoID); err != nil {
				b.Error(err)
				return
			}
			if _, err := s.Emisiones(repoID); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
