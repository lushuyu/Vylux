package migrations_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"io/fs"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"uuid"

	"Vylux/internal/db"
	"Vylux/migrations"
	"Vylux/tests/testutil"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"
)

//go:embed testdata/001_rewritten_v2_1.sql
var releasedV21Initial []byte

func TestStreamKeyBridgeConvergesReleasedMigrationHistories(t *testing.T) {
	rewrittenSum := sha256.Sum256(releasedV21Initial)
	if got, want := hex.EncodeToString(rewrittenSum[:]), "294885240e683429785965ac40eed76c572f8bce35b96d657683e3c6ce0adb4f"; got != want {
		t.Fatalf("released v2.1 migration 001 fixture digest = %s, want %s", got, want)
	}

	if testing.Short() {
		t.Skip("skipping PostgreSQL migration history test in short mode")
	}

	ctx := context.Background()
	databaseDSN := migrationTestDSN(ctx, t)
	admin, err := db.Connect(ctx, databaseDSN)
	if err != nil {
		t.Fatalf("connect migration test database: %v", err)
	}
	t.Cleanup(admin.Close)
	var serverVersionNum int
	if err := admin.QueryRow(ctx, "SELECT current_setting('server_version_num')::INTEGER").Scan(&serverVersionNum); err != nil {
		t.Fatalf("read PostgreSQL server version: %v", err)
	}

	oldInitial := migrationSubset(t, "001_initial.sql")
	releasedV20Initial, err := fs.ReadFile(migrations.FS, "001_initial.sql")
	if err != nil {
		t.Fatalf("read released v2.0 migration 001: %v", err)
	}
	forkInitial := migrationSubset(t, "001_initial.sql", "002_media_lifecycle.sql", "003_deployment_target.sql")
	rewrittenInitial := fstest.MapFS{
		"001_initial.sql": &fstest.MapFile{Data: releasedV21Initial, Mode: 0o644},
	}

	tests := []struct {
		name                  string
		initial               fs.FS
		seedLegacy            bool
		seedStream            bool
		legacyAfterBridge     int
		streamAfterBridge     int
		protectLegacyDown     bool
		protectStreamDown     bool
		legacyExistsAfterDown bool
		streamExistsAfterDown bool
	}{
		{
			name:                  "released_v2_0_001",
			initial:               oldInitial,
			seedLegacy:            true,
			legacyAfterBridge:     1,
			protectStreamDown:     true,
			legacyExistsAfterDown: true,
		},
		{
			name:                  "released_rewritten_v2_1_001",
			initial:               rewrittenInitial,
			seedStream:            true,
			streamAfterBridge:     1,
			protectLegacyDown:     true,
			streamExistsAfterDown: true,
		},
		{
			name:                  "fork_001_002_003",
			initial:               forkInitial,
			seedLegacy:            true,
			legacyAfterBridge:     1,
			legacyExistsAfterDown: true,
		},
		{
			name:                  "fresh_restored_001_002_003_004",
			legacyExistsAfterDown: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schemaDSN := newMigrationTestSchema(t, ctx, admin, databaseDSN)

			if tt.initial != nil {
				if err := db.Migrate(ctx, schemaDSN, tt.initial); err != nil {
					t.Fatalf("apply starting history: %v", err)
				}
			}
			pool, err := db.Connect(ctx, schemaDSN)
			if err != nil {
				t.Fatalf("connect history schema: %v", err)
			}
			defer pool.Close()

			const sourceHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			if tt.seedLegacy {
				if _, err := pool.Exec(ctx, `
					INSERT INTO encryption_keys
					    (hash, wrapped_key, wrap_nonce, kek_version, kid, scheme, key_uri)
					VALUES ($1, $2, $3, 'v1', 'legacy-kid', 'cbcs', $4)`,
					sourceHash, []byte("legacy-wrapped"), []byte("legacy-nonce"), "/api/key/"+sourceHash,
				); err != nil {
					t.Fatalf("seed legacy key: %v", err)
				}
			}
			if tt.seedStream {
				if _, err := pool.Exec(ctx, `
					INSERT INTO stream_encryption_keys
					    (id, source_hash, asset_type, packaging_type, wrapped_key, wrap_nonce, kek_version, kid, scheme)
					VALUES ('11111111-1111-4111-8111-111111111111', $1, 'video', 'hls', $2, $3, 'v1', 'stream-kid', 'cbcs')`,
					sourceHash, []byte("stream-wrapped"), []byte("stream-nonce"),
				); err != nil {
					t.Fatalf("seed stream key: %v", err)
				}
			}

			if err := db.Migrate(ctx, schemaDSN, migrations.FS); err != nil {
				t.Fatalf("apply current migrations: %v", err)
			}
			if err := db.Migrate(ctx, schemaDSN, migrations.FS); err != nil {
				t.Fatalf("re-apply current migrations: %v", err)
			}
			assertAppliedVersions(t, ctx, pool, []int64{1, 2, 3, 4})
			assertKeyTables(t, ctx, pool, true, true)
			assertKeyCounts(t, ctx, pool, sourceHash, tt.legacyAfterBridge, tt.streamAfterBridge)
			if tt.protectStreamDown {
				assertConcurrentStreamWriterBlocksDown(t, ctx, schemaDSN, pool)
			}
			assertPopulatedBridgeTableBlocksDown(t, ctx, schemaDSN, pool, tt.protectLegacyDown, tt.protectStreamDown)

			if _, err := pool.Exec(ctx, `
				INSERT INTO stream_encryption_keys
				    (id, source_hash, asset_type, packaging_type, wrapped_key, wrap_nonce)
				VALUES ('22222222-2222-4222-8222-222222222222', $1, 'document', 'hls', $2, $3)`,
				sourceHash, []byte("invalid"), []byte("invalid"),
			); err == nil {
				t.Fatal("invalid stream asset_type unexpectedly satisfied migration 004 constraints")
			}

			runGooseCommand(t, ctx, schemaDSN, "down")
			assertAppliedVersions(t, ctx, pool, []int64{1, 2, 3})
			assertKeyTables(t, ctx, pool, tt.legacyExistsAfterDown, tt.streamExistsAfterDown)

			if err := db.Migrate(ctx, schemaDSN, migrations.FS); err != nil {
				t.Fatalf("re-apply migration 004 after down: %v", err)
			}
			assertAppliedVersions(t, ctx, pool, []int64{1, 2, 3, 4})
			assertKeyTables(t, ctx, pool, true, true)
			assertKeyCounts(t, ctx, pool, sourceHash, tt.legacyAfterBridge, tt.streamAfterBridge)
		})
	}

	malformedCases := []struct {
		name            string
		initial         []byte
		old             string
		replacement     string
		wantError       string
		wantLegacyTable bool
		wantStreamTable bool
		minimumVersion  int
		wantLegacyNull  bool
	}{
		{
			name:            "wrong_primary_key",
			initial:         releasedV21Initial,
			old:             "    id             UUID        PRIMARY KEY,\n    source_hash    TEXT        NOT NULL,",
			replacement:     "    id             UUID        NOT NULL,\n    source_hash    TEXT        PRIMARY KEY,",
			wantError:       "requires the exact asset-scoped stream key constraints",
			wantStreamTable: true,
		},
		{
			name:            "same_named_wrong_check",
			initial:         releasedV21Initial,
			old:             "CONSTRAINT chk_stream_encryption_keys_asset_type CHECK (asset_type IN ('audio', 'video'))",
			replacement:     "CONSTRAINT chk_stream_encryption_keys_asset_type CHECK (TRUE)",
			wantError:       "requires the exact asset-scoped stream key constraints",
			wantStreamTable: true,
		},
		{
			name:            "same_named_wrong_unique",
			initial:         releasedV21Initial,
			old:             "CONSTRAINT uq_stream_encryption_keys_asset UNIQUE (source_hash, asset_type, packaging_type)",
			replacement:     "CONSTRAINT uq_stream_encryption_keys_asset UNIQUE (id, asset_type, packaging_type)",
			wantError:       "requires the exact asset-scoped stream key constraints",
			wantStreamTable: true,
		},
		{
			name:            "missing_stream_created_at_default",
			initial:         releasedV21Initial,
			old:             "    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),",
			replacement:     "    created_at     TIMESTAMPTZ NOT NULL,",
			wantError:       "found an incompatible stream_encryption_keys relation",
			wantStreamTable: true,
		},
		{
			name:            "missing_stream_source_hash_not_null",
			initial:         releasedV21Initial,
			old:             "    source_hash    TEXT        NOT NULL,",
			replacement:     "    source_hash    TEXT,",
			wantError:       "found an incompatible stream_encryption_keys relation",
			wantStreamTable: true,
		},
		{
			name:            "extra_stream_rejector_constraint",
			initial:         releasedV21Initial,
			old:             "    CONSTRAINT uq_stream_encryption_keys_asset UNIQUE (source_hash, asset_type, packaging_type)",
			replacement:     "    CONSTRAINT uq_stream_encryption_keys_asset UNIQUE (source_hash, asset_type, packaging_type),\n    CONSTRAINT vylux_test_reject_stream_keys CHECK (FALSE)",
			wantError:       "requires the exact asset-scoped stream key constraints",
			wantStreamTable: true,
		},
		{
			name:    "extra_stream_rejector_unique_index",
			initial: releasedV21Initial,
			old:     "CREATE INDEX IF NOT EXISTS idx_stream_encryption_keys_source_hash ON stream_encryption_keys (source_hash);",
			replacement: "CREATE INDEX IF NOT EXISTS idx_stream_encryption_keys_source_hash ON stream_encryption_keys (source_hash);\n" +
				"CREATE UNIQUE INDEX vylux_test_reject_stream_keys ON stream_encryption_keys (asset_type);",
			wantError:       "found an unsupported standalone unique key-table index",
			wantStreamTable: true,
		},
		{
			name:            "missing_legacy_created_at_default",
			initial:         releasedV20Initial,
			old:             "    key_uri     TEXT        NOT NULL DEFAULT '',\n    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()",
			replacement:     "    key_uri     TEXT        NOT NULL DEFAULT '',\n    created_at  TIMESTAMPTZ NOT NULL",
			wantError:       "found an incompatible encryption_keys relation",
			wantLegacyTable: true,
		},
		{
			name:            "missing_legacy_wrapped_key_not_null",
			initial:         releasedV20Initial,
			old:             "    wrapped_key BYTEA       NOT NULL,",
			replacement:     "    wrapped_key BYTEA,",
			wantError:       "found an incompatible encryption_keys relation",
			wantLegacyTable: true,
		},
		{
			name:            "extra_legacy_rejector_constraint",
			initial:         releasedV20Initial,
			old:             "    key_uri     TEXT        NOT NULL DEFAULT '',\n    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()",
			replacement:     "    key_uri     TEXT        NOT NULL DEFAULT '',\n    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),\n    CONSTRAINT vylux_test_reject_legacy_keys CHECK (FALSE)",
			wantError:       "requires the exact released encryption_keys constraints",
			wantLegacyTable: true,
		},
		{
			name:    "extra_legacy_rejector_unique_index",
			initial: releasedV20Initial,
			old:     "    key_uri     TEXT        NOT NULL DEFAULT '',\n    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()\n);",
			replacement: "    key_uri     TEXT        NOT NULL DEFAULT '',\n    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()\n);\n\n" +
				"CREATE UNIQUE INDEX vylux_test_reject_legacy_keys ON encryption_keys (scheme);",
			wantError:       "found an unsupported standalone unique key-table index",
			wantLegacyTable: true,
		},
		{
			name:    "unvalidated_legacy_not_null_constraint",
			initial: releasedV20Initial,
			old:     "    key_uri     TEXT        NOT NULL DEFAULT '',\n    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()\n);",
			replacement: "    key_uri     TEXT        NOT NULL DEFAULT '',\n    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()\n);\n\n" +
				"ALTER TABLE encryption_keys ALTER COLUMN wrapped_key DROP NOT NULL;\n" +
				"INSERT INTO encryption_keys (hash, wrapped_key, wrap_nonce) VALUES (repeat('a', 64), NULL, '\\x01'::bytea);\n" +
				"ALTER TABLE encryption_keys ADD CONSTRAINT vylux_test_legacy_wrapped_key_not_null NOT NULL wrapped_key NOT VALID;",
			wantError:       "found an incompatible not-null key-table constraint",
			wantLegacyTable: true,
			minimumVersion:  180000,
			wantLegacyNull:  true,
		},
		{
			name:    "no_inherit_stream_not_null_constraint",
			initial: releasedV21Initial,
			old:     "    CONSTRAINT uq_stream_encryption_keys_asset UNIQUE (source_hash, asset_type, packaging_type)\n);",
			replacement: "    CONSTRAINT uq_stream_encryption_keys_asset UNIQUE (source_hash, asset_type, packaging_type)\n);\n\n" +
				"ALTER TABLE stream_encryption_keys ALTER COLUMN wrapped_key DROP NOT NULL;\n" +
				"ALTER TABLE stream_encryption_keys ADD CONSTRAINT vylux_test_stream_wrapped_key_not_null NOT NULL wrapped_key NO INHERIT;",
			wantError:       "found an incompatible not-null key-table constraint",
			wantStreamTable: true,
			minimumVersion:  180000,
		},
	}
	for _, malformedCase := range malformedCases {
		t.Run(malformedCase.name, func(t *testing.T) {
			if serverVersionNum < malformedCase.minimumVersion {
				t.Skipf("requires PostgreSQL server_version_num >= %d", malformedCase.minimumVersion)
			}
			schemaDSN := newMigrationTestSchema(t, ctx, admin, databaseDSN)
			malformed := replaceExactlyOnce(
				t,
				append([]byte(nil), malformedCase.initial...),
				malformedCase.old,
				malformedCase.replacement,
			)
			malformedInitial := fstest.MapFS{
				"001_initial.sql": &fstest.MapFile{Data: malformed, Mode: 0o644},
			}
			if err := db.Migrate(ctx, schemaDSN, malformedInitial); err != nil {
				t.Fatalf("apply malformed starting history: %v", err)
			}
			pool, err := db.Connect(ctx, schemaDSN)
			if err != nil {
				t.Fatalf("connect malformed history schema: %v", err)
			}
			defer pool.Close()

			err = db.Migrate(ctx, schemaDSN, migrations.FS)
			if err == nil {
				t.Fatal("migration 004 unexpectedly accepted an incorrect key constraint")
			}
			if !strings.Contains(err.Error(), malformedCase.wantError) {
				t.Fatalf("malformed history migration error = %v, want %q", err, malformedCase.wantError)
			}
			assertAppliedVersions(t, ctx, pool, []int64{1, 2, 3})
			assertKeyTables(t, ctx, pool, malformedCase.wantLegacyTable, malformedCase.wantStreamTable)
			if malformedCase.wantLegacyNull {
				var nullRows int
				if err := pool.QueryRow(ctx, "SELECT count(*) FROM encryption_keys WHERE wrapped_key IS NULL").Scan(&nullRows); err != nil {
					t.Fatalf("count retained legacy NULL key rows: %v", err)
				}
				if nullRows != 1 {
					t.Fatalf("retained legacy NULL key rows = %d, want 1", nullRows)
				}
			}
		})
	}
}

func newMigrationTestSchema(t *testing.T, ctx context.Context, admin *db.Pool, databaseDSN string) string {
	t.Helper()
	schema := "vylux_m004_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop migration test schema: %v", err)
		}
	})
	return withSearchPath(t, databaseDSN, schema)
}

func replaceExactlyOnce(t *testing.T, input []byte, old, replacement string) []byte {
	t.Helper()
	if got := bytes.Count(input, []byte(old)); got != 1 {
		t.Fatalf("migration fixture replacement count for %q = %d, want 1", old, got)
	}
	return bytes.Replace(input, []byte(old), []byte(replacement), 1)
}

func migrationTestDSN(ctx context.Context, t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		return dsn
	}
	return testutil.StartPostgres(ctx, t).DSN
}

func migrationSubset(t *testing.T, names ...string) fstest.MapFS {
	t.Helper()
	result := make(fstest.MapFS, len(names))
	for _, name := range names {
		contents, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		result[name] = &fstest.MapFile{Data: contents, Mode: 0o644}
	}
	return result
}

func withSearchPath(t *testing.T, dsn, schema string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL DSN: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func runGooseCommand(t *testing.T, ctx context.Context, dsn, command string) {
	t.Helper()
	if err := gooseCommand(ctx, dsn, command); err != nil {
		t.Fatalf("goose %s: %v", command, err)
	}
}

func gooseCommand(ctx context.Context, dsn, command string) error {
	goose.SetBaseFS(migrations.FS)
	sqlDB, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	return goose.RunContext(ctx, command, sqlDB, ".")
}

func assertPopulatedBridgeTableBlocksDown(
	t *testing.T,
	ctx context.Context,
	dsn string,
	pool *db.Pool,
	populateLegacy bool,
	populateStream bool,
) {
	t.Helper()
	if !populateLegacy && !populateStream {
		return
	}

	const bridgeHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	wantError := ""
	if populateLegacy {
		if _, err := pool.Exec(ctx, `
			INSERT INTO encryption_keys
			    (hash, wrapped_key, wrap_nonce, kek_version, kid, scheme, key_uri)
			VALUES ($1, $2, $3, 'v1', 'bridge-legacy-kid', 'cbcs', $4)`,
			bridgeHash, []byte("legacy-wrapped"), []byte("legacy-nonce"), "/api/key/"+bridgeHash,
		); err != nil {
			t.Fatalf("populate bridge-created legacy table: %v", err)
		}
		wantError = "cannot drop populated encryption_keys compatibility table"
	}
	if populateStream {
		if _, err := pool.Exec(ctx, `
			INSERT INTO stream_encryption_keys
			    (id, source_hash, asset_type, packaging_type, wrapped_key, wrap_nonce, kek_version, kid, scheme)
			VALUES ('33333333-3333-4333-8333-333333333333', $1, 'video', 'hls', $2, $3, 'v1', 'bridge-stream-kid', 'cbcs')`,
			bridgeHash, []byte("stream-wrapped"), []byte("stream-nonce"),
		); err != nil {
			t.Fatalf("populate bridge-created stream table: %v", err)
		}
		wantError = "cannot drop populated stream_encryption_keys compatibility table"
	}

	err := gooseCommand(ctx, dsn, "down")
	if err == nil {
		t.Fatal("goose down unexpectedly dropped a populated migration 004 compatibility table")
	}
	if !strings.Contains(err.Error(), wantError) {
		t.Fatalf("goose down error = %v, want %q", err, wantError)
	}
	assertAppliedVersions(t, ctx, pool, []int64{1, 2, 3, 4})
	assertKeyTables(t, ctx, pool, true, true)
	assertKeyCounts(t, ctx, pool, bridgeHash, boolInt(populateLegacy), boolInt(populateStream))

	if populateLegacy {
		if _, err := pool.Exec(ctx, "DELETE FROM encryption_keys WHERE hash = $1", bridgeHash); err != nil {
			t.Fatalf("drain bridge-created legacy table: %v", err)
		}
	}
	if populateStream {
		if _, err := pool.Exec(ctx, "DELETE FROM stream_encryption_keys WHERE source_hash = $1", bridgeHash); err != nil {
			t.Fatalf("drain bridge-created stream table: %v", err)
		}
	}
}

func assertConcurrentStreamWriterBlocksDown(t *testing.T, ctx context.Context, dsn string, pool *db.Pool) {
	t.Helper()
	const bridgeHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin concurrent bridge writer: %v", err)
	}
	writerOpen := true
	defer func() {
		if writerOpen {
			_ = writer.Rollback(context.Background())
		}
	}()
	if _, err := writer.Exec(ctx, `
		INSERT INTO stream_encryption_keys
		    (id, source_hash, asset_type, packaging_type, wrapped_key, wrap_nonce, kek_version, kid, scheme)
		VALUES ('44444444-4444-4444-8444-444444444444', $1, 'video', 'hls', $2, $3, 'v1', 'concurrent-stream-kid', 'cbcs')`,
		bridgeHash, []byte("stream-wrapped"), []byte("stream-nonce"),
	); err != nil {
		t.Fatalf("insert concurrent bridge key: %v", err)
	}

	downResult := make(chan error, 1)
	go func() {
		downResult <- gooseCommand(context.Background(), dsn, "down")
	}()

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		var waiting bool
		if err := pool.QueryRow(waitCtx, `
			SELECT EXISTS (
			    SELECT 1
			    FROM pg_locks AS lock
			    JOIN pg_class AS relation ON relation.oid = lock.relation
			    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
			    WHERE namespace.nspname = current_schema()
			      AND relation.relname = 'stream_encryption_keys'
			      AND lock.mode = 'AccessExclusiveLock'
			      AND NOT lock.granted
			)`).Scan(&waiting); err != nil {
			_ = writer.Rollback(context.Background())
			writerOpen = false
			t.Fatalf("inspect migration 004 Down lock: %v", err)
		}
		if waiting {
			break
		}
		select {
		case <-waitCtx.Done():
			_ = writer.Rollback(context.Background())
			writerOpen = false
			t.Fatalf("migration 004 Down did not wait for the concurrent stream writer: %v", waitCtx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}

	if err := writer.Commit(ctx); err != nil {
		writerOpen = false
		t.Fatalf("commit concurrent bridge writer: %v", err)
	}
	writerOpen = false

	select {
	case err := <-downResult:
		if err == nil {
			t.Fatal("migration 004 Down unexpectedly dropped a table after a concurrent writer committed")
		}
		if want := "cannot drop populated stream_encryption_keys compatibility table"; !strings.Contains(err.Error(), want) {
			t.Fatalf("concurrent goose down error = %v, want %q", err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("migration 004 Down did not finish after the concurrent writer committed")
	}

	assertAppliedVersions(t, ctx, pool, []int64{1, 2, 3, 4})
	assertKeyTables(t, ctx, pool, true, true)
	assertKeyCounts(t, ctx, pool, bridgeHash, 0, 1)
	if _, err := pool.Exec(ctx, "DELETE FROM stream_encryption_keys WHERE source_hash = $1", bridgeHash); err != nil {
		t.Fatalf("drain concurrent bridge key: %v", err)
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func assertAppliedVersions(t *testing.T, ctx context.Context, pool *db.Pool, want []int64) {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT version_id
		FROM goose_db_version
		WHERE is_applied = TRUE AND version_id > 0
		ORDER BY version_id`)
	if err != nil {
		t.Fatalf("list Goose versions: %v", err)
	}
	defer rows.Close()
	var got []int64
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			t.Fatalf("scan Goose version: %v", err)
		}
		got = append(got, version)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read Goose versions: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("applied Goose versions = %v, want %v", got, want)
	}
}

func assertKeyTables(t *testing.T, ctx context.Context, pool *db.Pool, wantLegacy, wantStream bool) {
	t.Helper()
	var legacyExists, streamExists bool
	if err := pool.QueryRow(ctx, `
		SELECT to_regclass('encryption_keys') IS NOT NULL,
		       to_regclass('stream_encryption_keys') IS NOT NULL`).Scan(&legacyExists, &streamExists); err != nil {
		t.Fatalf("inspect key tables: %v", err)
	}
	if legacyExists != wantLegacy || streamExists != wantStream {
		t.Fatalf(
			"key table presence = legacy:%t stream:%t, want legacy:%t stream:%t",
			legacyExists,
			streamExists,
			wantLegacy,
			wantStream,
		)
	}
}

func assertKeyCounts(t *testing.T, ctx context.Context, pool *db.Pool, hash string, wantLegacy, wantStream int) {
	t.Helper()
	var legacyCount, streamCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM encryption_keys WHERE hash = $1", hash).Scan(&legacyCount); err != nil {
		t.Fatalf("count legacy keys: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM stream_encryption_keys WHERE source_hash = $1", hash).Scan(&streamCount); err != nil {
		t.Fatalf("count stream keys: %v", err)
	}
	if legacyCount != wantLegacy || streamCount != wantStream {
		t.Fatalf(
			"key row counts = legacy:%d stream:%d, want legacy:%d stream:%d",
			legacyCount,
			streamCount,
			wantLegacy,
			wantStream,
		)
	}
}
