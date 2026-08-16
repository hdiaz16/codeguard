package engines

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Applies no puede mirar el CONTENIDO de los archivos, sólo su ruta y su estado.
//
// Es un contrato que hoy se cumple sin que nadie lo escribiera, y de él depende
// algo que ya está en producción: `daemon.CapasDelRepo` contesta "¿qué capas
// vigilan mi repo?" construyendo un Input SINTÉTICO —el árbol entero presentado
// como modificado, con SHA256 vacío— y preguntándole a cada Applies. Eso es
// fiel mientras Applies decida sólo por Path y Status.
//
// El día que alguien escriba un Applies que mire SHA256, esa respuesta pasará a
// ser falsa EN SILENCIO: el motor diría "no aplico" por un contenido vacío que
// nadie le dio, la capa desaparecería del panel y ninguna prueba se enteraría.
// Un fallo así no se encuentra leyendo, porque los dos lados son razonables por
// separado. Lo cazó el validador señalando que el contrato era tácito.
//
// LO QUE NO RECONOCE, para que nadie lo confunda con una garantía: sólo mira el
// cuerpo del propio método Applies. Si Applies llama a un ayudante y es EL
// AYUDANTE quien lee el contenido, esto no lo ve. Su trabajo es cortar la vía
// directa y dejar constancia escrita del contrato, no resistir a quien quiera
// rodearlo.
func TestAppliesDecidePorRutaYEstadoNoPorContenido(t *testing.T) {
	raiz := "."
	fset := token.NewFileSet()

	revisados := 0
	err := filepath.WalkDir(raiz, func(ruta string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		archivo, err := parser.ParseFile(fset, ruta, nil, 0)
		if err != nil {
			return nil // un archivo con etiquetas de compilación de otro sistema
		}
		ast.Inspect(archivo, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "Applies" || fn.Recv == nil || fn.Body == nil {
				return true
			}
			revisados++
			ast.Inspect(fn.Body, func(m ast.Node) bool {
				sel, ok := m.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "SHA256" {
					return true
				}
				t.Errorf("%s: Applies mira el contenido del archivo (.SHA256).\n"+
					"Applies tiene que decidir por ruta y estado. daemon.CapasDelRepo le "+
					"pregunta con un Input sintético sin contenido para saber qué capas "+
					"vigilan un repo; en cuanto un Applies mire el SHA, esa respuesta será "+
					"falsa y nadie se enterará.", fset.Position(sel.Pos()))
				return true
			})
			return false
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Sin esto, mover los motores de sitio dejaría la prueba mirando cero
	// funciones y pasando en verde para siempre. Son 17 implementaciones
	// (los 16 de la etapa 2 más gitleaks); se exige holgadamente menos por no
	// atar la prueba al número exacto, que cambia cada vez que se añade un motor.
	if revisados < 12 {
		t.Fatalf("sólo se revisaron %d implementaciones de Applies: o se movieron de "+
			"sitio o esta prueba dejó de vigilar nada", revisados)
	}
}
