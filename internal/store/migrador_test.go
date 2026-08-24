package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/migrations"
)

// El contrato del migrador con checksum ([07]/[08], turnos 89-93): el nombre
// del archivo dejó de ser la única identidad de una migración. Editar un SQL
// ya aplicado se saltaba EN SILENCIO y la divergencia de esquema se propagaba
// por los tres binarios sin una sola señal.

func TestUnaMigracionEditadaDespuesDeAplicadaAbortaOpen(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "bd.db")
	s, err := Open(ruta)
	if err != nil {
		t.Fatal(err)
	}
	// Se simula la edición: el checksum registrado deja de corresponder al
	// SQL embebido (equivale a que el binario nuevo traiga otro 001).
	if _, err := s.db.Exec(`UPDATE schema_migrations SET checksum = 'deadbeef' WHERE version = '001_init.sql'`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	_, err = Open(ruta)
	if err == nil {
		t.Fatal("una migración divergente abrió la BD: todo lo que se escriba encima hereda la ambigüedad")
	}
	for _, quiero := range []string{"001_init.sql", "Remedio"} {
		if !strings.Contains(err.Error(), quiero) {
			t.Errorf("el error debe nombrar la migración y el remedio; falta %q en: %v", quiero, err)
		}
	}
}

func TestUnaFilaAnteriorAlChecksumSeAdoptaUnaVez(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "bd.db")
	s, err := Open(ruta)
	if err != nil {
		t.Fatal(err)
	}
	// Fila como la dejaba el binario viejo: sin checksum.
	if _, err := s.db.Exec(`UPDATE schema_migrations SET checksum = NULL, checksum_adopted_at = NULL WHERE version = '002_sync.sql'`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := Open(ruta)
	if err != nil {
		t.Fatalf("una fila legacy no puede impedir abrir: se adopta (trust-on-first-use): %v", err)
	}
	defer s2.Close()
	var checksum, adoptado string
	if err := s2.db.QueryRow(`SELECT checksum, COALESCE(checksum_adopted_at,'') FROM schema_migrations WHERE version = '002_sync.sql'`).
		Scan(&checksum, &adoptado); err != nil {
		t.Fatal(err)
	}
	cat, _ := migrations.Catalogo()
	var esperado string
	for _, m := range cat {
		if m.Nombre == "002_sync.sql" {
			esperado = m.Checksum
		}
	}
	if checksum != esperado {
		t.Errorf("el checksum adoptado no es el del SQL embebido: %q", checksum)
	}
	if adoptado == "" {
		t.Error("la adopción debe quedar fechada (checksum_adopted_at): es adopción auditable, no verificación histórica")
	}
}

// La aceptación firmada del plan: N procesos contra una BD vacía → UN
// migrador gana, los demás esperan en el mutex nombrado y todos terminan con
// el MISMO esquema. Procesos de verdad, no goroutines: el busy_timeout y el
// mutex Local\ solo se prueban entre procesos.
func TestVeinteProcesosContraUnaBDVacia(t *testing.T) {
	if os.Getenv("CG_HIJO_MIGRADOR") != "" {
		s, err := Open(os.Getenv("CG_HIJO_MIGRADOR"))
		if err != nil {
			os.Exit(3)
		}
		s.Close()
		os.Exit(0)
	}
	if testing.Short() {
		t.Skip("lanza 20 procesos")
	}
	ruta := filepath.Join(t.TempDir(), "bd.db")
	const n = 20
	hijos := make([]*exec.Cmd, n)
	for i := range hijos {
		hijos[i] = exec.Command(os.Args[0], "-test.run=^TestVeinteProcesosContraUnaBDVacia$", "-test.timeout=60s")
		hijos[i].Env = append(os.Environ(), "CG_HIJO_MIGRADOR="+ruta)
		if err := hijos[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	for i, h := range hijos {
		if err := h.Wait(); err != nil {
			t.Errorf("el proceso %d no pudo abrir/migrar: %v", i, err)
		}
	}
	s, err := Open(ruta)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cat, _ := migrations.Catalogo()
	var aplicadas int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&aplicadas); err != nil {
		t.Fatal(err)
	}
	if aplicadas != len(cat) {
		t.Errorf("migraciones aplicadas = %d, catálogo = %d: alguien migró de más o de menos", aplicadas, len(cat))
	}
}
