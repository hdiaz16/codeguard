// Package migrations embebe el DDL portable numerado (sección 9).
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
