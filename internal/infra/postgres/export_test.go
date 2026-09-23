package postgres

// This file compiles only into the test binary, so migrateDown stays unreachable from
// any production consumer while postgres_test can still drive the Down direction.
var (
	MigrateDown = migrateDown
	MigrateTo   = migrateTo
)
