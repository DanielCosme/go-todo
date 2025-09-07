package migrations

import "embed"

//go:embed "sqlite"
var MigrationsFS embed.FS
