// Fixture aparte: el import anónimo de pprof registra sus rutas como efecto
// secundario, así que tiene que estar solo en su archivo para no contaminar
// los demás casos.
package testdata

// ruleid: go-debug-en-prod
import _ "net/http/pprof"
