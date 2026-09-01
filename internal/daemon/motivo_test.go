package daemon

// Que Response TENGA sitio para el motivo no sirve de nada si el daemon no lo
// rellena. Esta prueba mira el eslabón que faltaba: la respuesta que sale de
// Analyze, que es literalmente lo que el hook recibe por el pipe.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
)

// repoQueExcluyeTodo deja un repo enrolado cuya configuración excluye lo que se
// va a mandar. Es la vía por la que el pipeline devuelve Skipped en la etapa 0,
// sin arrancar ningún motor.
func repoQueExcluyeTodo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	dir := filepath.Join(repo, ".codeguard")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "version: 1\nrulepack: \"2026.08.2\"\npaths:\n  exclude:\n    - \"vendor/**\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestElMotivoDeUnAnalisisOmitidoLlegaALaRespuesta(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	repo := repoQueExcluyeTodo(t)

	s := &Server{}
	resp := s.Analyze(context.Background(), &ipc.Request{
		RunID:        "r-prueba",
		RepoRoot:     repo,
		AnalysisRoot: repo,
		StagedFiles:  []gitdiff.ChangedFile{{Path: "vendor/lib.go", Status: "M"}},
		DeadlineMs:   5000,
	})

	if resp.Verdict != "skipped" {
		t.Fatalf("con todo excluido el veredicto debe ser skipped, y fue %q", resp.Verdict)
	}
	if resp.Reason == "" {
		t.Fatal("el daemon no copió el motivo: el hook recibirá un análisis omitido " +
			"sin poder decir POR QUÉ, que es justo lo que se viene a arreglar")
	}
	// Igualdad EXACTA contra la constante, no un Contains: el hook compara este
	// texto con pipeline.MotivoTodoExcluido para elegir el tono del mensaje
	// (decisión del equipo, en neutro; avería, con la línea fuerte). Si el
	// daemon entregara una variante —un prefijo, otra redacción—, el tono se
	// caería al de avería sin que nada se pusiera rojo.
	if resp.Reason != pipeline.MotivoTodoExcluido {
		t.Errorf("el motivo no llegó tal cual lo redactó el pipeline:\n  llegó:    %q\n  esperado: %q",
			resp.Reason, pipeline.MotivoTodoExcluido)
	}
}

// El otro Skipped del daemon, que no viene del pipeline sino de aquí mismo: si
// la configuración no se puede leer, Analyze corta por su cuenta. También tiene
// que decir por qué, o el hook enseñará un "no se analizó nada" mudo.
//
// Son DOS ramas y el remedio de cada una es distinto —`codeguard init` contra
// arreglar el YAML—, así que se prueban las dos por separado. La del error se
// quedó sin cubrir en el primer montaje, y es justo la que arrastra el mensaje
// de koanf: llega en tres líneas, y por eso el hook lo aplana antes de
// imprimirlo (ver TestUnMotivoDeOtroProcesoNoPuedeDibujarUnaLineaFalsa).
func TestElSkippedPropioDelDaemonTambienDiceSuMotivo(t *testing.T) {
	t.Run("repo no enrolado", func(t *testing.T) {
		t.Setenv("LOCALAPPDATA", t.TempDir())
		resp := analizar(t, t.TempDir()) // sin .codeguard/config.yaml

		if resp.Verdict != "skipped" {
			t.Fatalf("sin config el veredicto debe ser skipped, y fue %q", resp.Verdict)
		}
		if resp.Reason == "" {
			t.Fatal("el daemon se saltó el análisis por su cuenta y no dijo por qué")
		}
		// El motivo tiene que ser el del repo sin enrolar, no el del archivo
		// roto: mandan a sitios distintos. Con un `Reason != ""` a secas, las
		// dos ramas podrían decir lo mismo y la prueba seguiría verde.
		if !strings.Contains(resp.Reason, "no enrolado") {
			t.Errorf("un repo sin config no está roto, está sin enrolar: %q", resp.Reason)
		}
	})

	// La config EXISTE y no casa con el esquema: `err != nil`. Es el caso del
	// desarrollador que editó el YAML a mano, y el que llega al hook por la
	// carrera —la config cambia entre la lectura del hook y la del daemon—.
	t.Run("config ilegible", func(t *testing.T) {
		t.Setenv("LOCALAPPDATA", t.TempDir())
		repo := t.TempDir()
		dir := filepath.Join(repo, ".codeguard")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// `paths` espera un mapa: un string ahí rompe el Unmarshal, que es el
		// error que trae el volcado multilínea.
		roto := "version: 1\nrulepack: \"2026.08.2\"\npaths: \"esto-no-es-un-mapa\"\n"
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(roto), 0o644); err != nil {
			t.Fatal(err)
		}

		resp := analizar(t, repo)

		if resp.Verdict != "skipped" {
			t.Fatalf("con la config ilegible el veredicto debe ser skipped, y fue %q", resp.Verdict)
		}
		if resp.Reason == "" {
			t.Fatal("la config no se pudo leer y el daemon no dijo nada: el hook enseñaría " +
				"un «no se analizó nada» mudo en el único caso que SÍ hay que arreglar")
		}
		if !strings.Contains(resp.Reason, "no se pudo leer") {
			t.Errorf("el motivo no distingue el archivo roto del repo sin enrolar: %q", resp.Reason)
		}
		// Y el detalle del error viaja: sin él, el dev sabe que su YAML está mal
		// pero no QUÉ está mal, que es la mitad útil.
		if !strings.Contains(resp.Reason, "paths") {
			t.Errorf("el motivo no dice qué parte del YAML falla: %q", resp.Reason)
		}
	})
}

// analizar corre el Analyze de verdad contra un repo, que es lo que el hook
// recibe por el pipe.
func analizar(t *testing.T, repo string) *ipc.Response {
	t.Helper()
	s := &Server{}
	return s.Analyze(context.Background(), &ipc.Request{
		RunID:        "r-prueba",
		RepoRoot:     repo,
		AnalysisRoot: repo,
		StagedFiles:  []gitdiff.ChangedFile{{Path: "a.go", Status: "M"}},
		DeadlineMs:   5000,
	})
}

// Un análisis normal no inventa motivo: el campo es del caso omitido y en el
// resto tiene que ir vacío, o el hook acabaría enseñando una explicación de
// algo que sí se revisó.
func TestUnAnalisisNormalNoLlevaMotivo(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	repo := repoQueExcluyeTodo(t)

	s := &Server{}
	resp := s.Analyze(context.Background(), &ipc.Request{
		RunID:        "r-prueba",
		RepoRoot:     repo,
		AnalysisRoot: repo,
		StagedFiles:  []gitdiff.ChangedFile{{Path: "notas.txt", Status: "M"}},
		DeadlineMs:   5000,
	})

	if resp.Verdict == "skipped" {
		t.Fatalf("un archivo no excluido tenía que analizarse: %q", resp.Reason)
	}
	if resp.Reason != "" {
		t.Errorf("un análisis que SÍ corrió no puede traer motivo de omisión: %q", resp.Reason)
	}
}
