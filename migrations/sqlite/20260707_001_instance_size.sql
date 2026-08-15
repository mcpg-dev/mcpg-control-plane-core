-- Instance size class (`s` | `m` | `l` | `xl`, lowercase). See the postgres
-- mirror for the rationale.
ALTER TABLE instances ADD COLUMN size TEXT NOT NULL DEFAULT 's';
