-- +goose Up

-- Version 2.0 shipped encryption_keys in migration 001. Version 2.1 rewrote
-- that already-released migration to create stream_encryption_keys instead.
-- Goose records only migration versions, so this forward bridge must converge
-- both histories without interpreting one legacy video key as one or more
-- asset-scoped stream keys.
CREATE TEMP TABLE vylux_migration_004_preexisting_tables (
    legacy_key_table BOOLEAN NOT NULL,
    stream_key_table BOOLEAN NOT NULL
) ON COMMIT DROP;

INSERT INTO vylux_migration_004_preexisting_tables (legacy_key_table, stream_key_table)
VALUES (
    to_regclass('encryption_keys') IS NOT NULL,
    to_regclass('stream_encryption_keys') IS NOT NULL
);

-- Keep the released v2.0 read model available for old playlists whose key URI
-- contains the source hash. New writers never insert into this table.
CREATE TABLE IF NOT EXISTS encryption_keys (
    hash        TEXT        PRIMARY KEY,
    wrapped_key BYTEA       NOT NULL,
    wrap_nonce  BYTEA       NOT NULL,
    kek_version TEXT        NOT NULL DEFAULT 'v1',
    kid         TEXT        NOT NULL DEFAULT '',
    scheme      TEXT        NOT NULL DEFAULT 'cbcs',
    key_uri     TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- All new audio and video protection continues to use UUID-backed,
-- asset-scoped stream rows.
CREATE TABLE IF NOT EXISTS stream_encryption_keys (
    id             UUID        PRIMARY KEY,
    source_hash    TEXT        NOT NULL,
    asset_type     TEXT        NOT NULL,
    packaging_type TEXT        NOT NULL,
    wrapped_key    BYTEA       NOT NULL,
    wrap_nonce     BYTEA       NOT NULL,
    kek_version    TEXT        NOT NULL DEFAULT 'v1',
    kid            TEXT        NOT NULL DEFAULT '',
    scheme         TEXT        NOT NULL DEFAULT 'cbcs',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_stream_encryption_keys_asset_type CHECK (asset_type IN ('audio', 'video')),
    CONSTRAINT chk_stream_encryption_keys_packaging_type CHECK (packaging_type IN ('hls')),
    CONSTRAINT uq_stream_encryption_keys_asset UNIQUE (source_hash, asset_type, packaging_type)
);

CREATE INDEX IF NOT EXISTS idx_stream_encryption_keys_source_hash ON stream_encryption_keys (source_hash);

-- Mark only tables created by this bridge. The Down path uses the markers to
-- avoid dropping a table that belonged to the database's original 001 history.
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT (SELECT legacy_key_table FROM vylux_migration_004_preexisting_tables) THEN
        COMMENT ON TABLE encryption_keys IS 'vylux:migration:004-created';
    END IF;
    IF NOT (SELECT stream_key_table FROM vylux_migration_004_preexisting_tables) THEN
        COMMENT ON TABLE stream_encryption_keys IS 'vylux:migration:004-created';
    END IF;
END;
$$;
-- +goose StatementEnd

-- Fail closed if an unexpected pre-existing relation only happened to share a
-- required table name. The exact released histories satisfy these contracts.
-- +goose StatementBegin
DO $$
DECLARE
    legacy_columns TEXT[];
    stream_columns TEXT[];
    legacy_constraints TEXT[];
    stream_constraints TEXT[];
BEGIN
    SELECT array_agg(
        column_name || ':' || data_type || ':' || is_nullable || ':'
        || COALESCE(column_default, '<none>')
        ORDER BY ordinal_position
    )
    INTO legacy_columns
    FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'encryption_keys';

    IF legacy_columns IS DISTINCT FROM ARRAY[
        'hash:text:NO:<none>',
        'wrapped_key:bytea:NO:<none>',
        'wrap_nonce:bytea:NO:<none>',
        'kek_version:text:NO:''v1''::text',
        'kid:text:NO:''''::text',
        'scheme:text:NO:''cbcs''::text',
        'key_uri:text:NO:''''::text',
        'created_at:timestamp with time zone:NO:now()'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'migration 004 found an incompatible encryption_keys relation';
    END IF;

    SELECT array_agg(
        column_name || ':' || data_type || ':' || is_nullable || ':'
        || COALESCE(column_default, '<none>')
        ORDER BY ordinal_position
    )
    INTO stream_columns
    FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'stream_encryption_keys';

    IF stream_columns IS DISTINCT FROM ARRAY[
        'id:uuid:NO:<none>',
        'source_hash:text:NO:<none>',
        'asset_type:text:NO:<none>',
        'packaging_type:text:NO:<none>',
        'wrapped_key:bytea:NO:<none>',
        'wrap_nonce:bytea:NO:<none>',
        'kek_version:text:NO:''v1''::text',
        'kid:text:NO:''''::text',
        'scheme:text:NO:''cbcs''::text',
        'created_at:timestamp with time zone:NO:now()'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'migration 004 found an incompatible stream_encryption_keys relation';
    END IF;

    SELECT array_agg(
        conname || ':' || contype::TEXT || ':' || pg_get_constraintdef(oid, FALSE)
        ORDER BY conname
    )
    INTO legacy_constraints
    FROM pg_constraint
    WHERE conrelid = to_regclass('encryption_keys');

    IF legacy_constraints IS DISTINCT FROM ARRAY[
        'encryption_keys_pkey:p:PRIMARY KEY (hash)'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'migration 004 requires the exact released encryption_keys constraints';
    END IF;

    SELECT array_agg(
        conname || ':' || contype::TEXT || ':' || pg_get_constraintdef(oid, FALSE)
        ORDER BY conname
    )
    INTO stream_constraints
    FROM pg_constraint
    WHERE conrelid = to_regclass('stream_encryption_keys');

    IF stream_constraints IS DISTINCT FROM ARRAY[
        'chk_stream_encryption_keys_asset_type:c:CHECK ((asset_type = ANY (ARRAY[''audio''::text, ''video''::text])))',
        'chk_stream_encryption_keys_packaging_type:c:CHECK ((packaging_type = ''hls''::text))',
        'stream_encryption_keys_pkey:p:PRIMARY KEY (id)',
        'uq_stream_encryption_keys_asset:u:UNIQUE (source_hash, asset_type, packaging_type)'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'migration 004 requires the exact asset-scoped stream key constraints';
    END IF;

    -- Constraint-backed primary/unique indexes were validated above. A
    -- standalone unique index can still reject otherwise valid runtime rows,
    -- so fail closed without rejecting harmless operator-added read indexes.
    IF EXISTS (
        SELECT 1
        FROM pg_index AS key_index
        WHERE key_index.indrelid IN (
            to_regclass('encryption_keys'),
            to_regclass('stream_encryption_keys')
        )
          AND key_index.indisunique
          AND NOT EXISTS (
              SELECT 1
              FROM pg_constraint AS key_constraint
              WHERE key_constraint.conindid = key_index.indexrelid
          )
    ) THEN
        RAISE EXCEPTION 'migration 004 found an unsupported standalone unique key-table index';
    END IF;
END;
$$;
-- +goose StatementEnd

DROP TABLE vylux_migration_004_preexisting_tables;

-- +goose Down

-- Remove only the compatibility relation that this migration created for the
-- database's original 001 history. Marker loss fails safe by retaining data,
-- and a populated compatibility relation must be drained by a forward
-- migration rather than destroyed by rollback.
-- Lock before the later emptiness check so an in-flight writer either commits
-- first and makes the rollback fail, or starts only after the migration ends.
-- +goose StatementBegin
DO $$
BEGIN
    IF to_regclass('stream_encryption_keys') IS NOT NULL
       AND obj_description(to_regclass('stream_encryption_keys'), 'pg_class') = 'vylux:migration:004-created' THEN
        LOCK TABLE stream_encryption_keys IN ACCESS EXCLUSIVE MODE;
    END IF;

    IF to_regclass('encryption_keys') IS NOT NULL
       AND obj_description(to_regclass('encryption_keys'), 'pg_class') = 'vylux:migration:004-created' THEN
        LOCK TABLE encryption_keys IN ACCESS EXCLUSIVE MODE;
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE
    bridge_table_has_rows BOOLEAN;
BEGIN
    IF to_regclass('stream_encryption_keys') IS NOT NULL
       AND obj_description(to_regclass('stream_encryption_keys'), 'pg_class') = 'vylux:migration:004-created' THEN
        SELECT EXISTS (SELECT 1 FROM stream_encryption_keys)
        INTO bridge_table_has_rows;
        IF bridge_table_has_rows THEN
            RAISE EXCEPTION 'migration 004 cannot drop populated stream_encryption_keys compatibility table';
        END IF;
        DROP TABLE stream_encryption_keys;
    END IF;

    IF to_regclass('encryption_keys') IS NOT NULL
       AND obj_description(to_regclass('encryption_keys'), 'pg_class') = 'vylux:migration:004-created' THEN
        SELECT EXISTS (SELECT 1 FROM encryption_keys)
        INTO bridge_table_has_rows;
        IF bridge_table_has_rows THEN
            RAISE EXCEPTION 'migration 004 cannot drop populated encryption_keys compatibility table';
        END IF;
        DROP TABLE encryption_keys;
    END IF;
END;
$$;
-- +goose StatementEnd
