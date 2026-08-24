package pipeline

import (
	"context"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/gitdiff"
)

// correrConMigracionSuelta reproduce el repo donde se midió el fallo: enrolado,
// con `paths.migrations` vacío, y un commit que cambia el esquema.
func correrConMigracionSuelta(t *testing.T) *Result {
	t.Helper()
	cfg := &config.Config{Rulepack: "test", RepoRoot: t.TempDir(), MaxDiffLines: 2000}
	res, err := Run(context.Background(), Options{
		Config: cfg,
		Diff: &gitdiff.Diff{
			Files: []gitdiff.ChangedFile{{Path: "db/002_moneda.sql", Status: "M"}},
			Lines: 3,
		},
	})
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	return res
}

// Cambiar el esquema sin que la compuerta lo mire tiene que DECIRSE.
//
// Es la mitad del arreglo que `codeguard init` no puede dar: init sólo toca los
// repos que nazcan de ahora en adelante, y el repo donde se midió el fallo ya
// estaba enrolado con `paths.migrations: []`. Sin este aviso, esos repos se
// quedan callados para siempre.
func TestUnaMigracionFueraDeLaListaSeAnuncia(t *testing.T) {
	sql := []gitdiff.ChangedFile{{Path: "db/002_moneda.sql", Status: "M"}}

	for _, c := range []struct {
		nombre   string
		cfg      *config.Config
		files    []gitdiff.ChangedFile
		seQueja  bool
		porqueNo string
	}{
		{
			nombre:  "la lista vacía con una migración en el commit: el caso medido",
			cfg:     &config.Config{},
			files:   sql,
			seQueja: true,
		},
		{
			nombre: "la lista la cubre: nada que decir",
			cfg: &config.Config{Paths: config.Paths{
				Migrations: []string{"db/*.sql"},
			}},
			files:   sql,
			seQueja: false,
		},
		{
			nombre: "la lista existe pero apunta a otro sitio: sigue sin vigilarse",
			cfg: &config.Config{Paths: config.Paths{
				Migrations: []string{"migrations/*.sql"},
			}},
			files:   sql,
			seQueja: true,
		},
		{
			nombre:  "un .sql que no es migración: no se da la lata",
			cfg:     &config.Config{},
			files:   []gitdiff.ChangedFile{{Path: "queries/get_user.sql", Status: "M"}},
			seQueja: false,
			porqueNo: "una consulta fuera de paths.migrations es lo correcto; " +
				"quejarse de ella cada día enseña a ignorar el aviso",
		},
		{
			nombre: "otro motor declarado: squawk no aplica y no es un descuido",
			cfg: &config.Config{Paths: config.Paths{
				MigrationsDialect: "sqlite",
			}},
			files:    sql,
			seQueja:  false,
			porqueNo: "mandar a editar paths.migrations no le arreglaría nada al dev",
		},
		{
			nombre:  "la migración se borra: no hay esquema nuevo que revisar",
			cfg:     &config.Config{},
			files:   []gitdiff.ChangedFile{{Path: "db/002_moneda.sql", Status: "D"}},
			seQueja: false,
		},
		{
			nombre:  "sin SQL en el commit",
			cfg:     &config.Config{},
			files:   []gitdiff.ChangedFile{{Path: "main.go", Status: "M"}},
			seQueja: false,
		},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			got := migracionSinVigilar(c.cfg, c.files)
			if (got != "") != c.seQueja {
				t.Errorf("se esperaba queja=%v y salió %q. %s", c.seQueja, got, c.porqueNo)
			}
			// La etiqueta viaja al veredicto y la leen el hook y el CI: tiene que
			// ser la misma cadena por los dos caminos, no un texto libre.
			if c.seQueja && got != "squawk:migracion-sin-vigilar" {
				t.Errorf("etiqueta inesperada: %q", got)
			}
		})
	}
}

// El aviso tiene que llegar al Result, no quedarse en la función. Es la
// diferencia entre que el hook lo imprima ("capas no revisadas: …") y que no
// exista para nadie.
func TestElAvisoLlegaAlVeredicto(t *testing.T) {
	res := correrConMigracionSuelta(t)
	for _, d := range res.Degraded {
		if d == "squawk:migracion-sin-vigilar" {
			return
		}
	}
	t.Errorf("el análisis no dijo que la migración quedó sin vigilar; Degraded=%v", res.Degraded)
}
