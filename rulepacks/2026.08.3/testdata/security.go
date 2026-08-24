// Fixture de semgrep --test — no es código del producto.
package fixtures

import (
	"database/sql"
	"strconv"
)

func buscarUsuario(db *sql.DB, id int) {
	// ruleid: go-sql-concat
	rows, err := db.Query("SELECT nombre FROM usuarios WHERE id = " + strconv.Itoa(id))
	_ = rows
	_ = err
}

func buscarUsuarioSeguro(db *sql.DB, id int) {
	// ok: go-sql-concat
	rows, err := db.Query("SELECT nombre FROM usuarios WHERE id = ?", id)
	_ = rows
	_ = err
}

func exportarEventos(db *sql.DB, repo string) {
	consulta := "SELECT id FROM eventos WHERE repo = '" + repo + "'"
	// ruleid: go-sql-concat-en-variable
	rows, err := db.Query(consulta)
	_ = rows
	_ = err
}

func listarEventos(db *sql.DB) {
	consulta := "SELECT id FROM eventos"
	consulta += " ORDER BY fecha DESC"
	// ok: go-sql-concat-en-variable
	rows, err := db.Query(consulta)
	_ = rows
	_ = err
}
