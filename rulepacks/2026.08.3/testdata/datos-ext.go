// Fixture de semgrep --test — no es código del producto.
// Casos de prueba del pilar datos (stem datos-ext), lenguaje Go.
package fixtures

import (
	"fmt"
	"log"
)

// Repositorio simula un ORM mínimo para los casos de transacción.
type Repositorio struct{}

func (r *Repositorio) Create(v interface{}) {}

func (r *Repositorio) Update(v interface{}) {}

func (r *Repositorio) Begin() *Repositorio { return r }

func (r *Repositorio) Commit() {}

// --- go-dinero-float ------------------------------------------------------------
// Factura modela un cobro del corpus de pruebas.
type Factura struct {
	// ruleid: go-dinero-float
	ImporteTotal float64
	// ok: go-dinero-float
	Latitud float64
}

// --- log-dato-sensible ----------------------------------------------------------
func registrarSesion(token string) {
	// ruleid: log-dato-sensible
	log.Printf("token emitido: %s", token)
	// ok: log-dato-sensible
	fmt.Println("token restringido: consulte la ayuda del comando")
}

// --- escrituras-sin-transaccion-go ------------------------------------------------
func guardarPedido(conn *Repositorio, pedido, reserva interface{}) {
	// ruleid: escrituras-sin-transaccion-go
	conn.Create(pedido)
	conn.Update(reserva)
}

func guardarPedidoAtomico(db *Repositorio, pedido, reserva interface{}) {
	tx := db.Begin()
	// ok: escrituras-sin-transaccion-go
	tx.Create(pedido)
	tx.Update(reserva)
	tx.Commit()
}
