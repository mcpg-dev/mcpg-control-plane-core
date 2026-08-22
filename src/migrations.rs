//! The schema migrations, embedded from this crate's own tree.
//!
//! Consumers run them through these migrators instead of pointing
//! `sqlx::migrate!` into this crate's directory by relative path — a
//! compile-time path into a sibling crate's tree does not survive
//! standalone packaging, where each crate ships only its own subtree.

/// SQLite schema migrations (`migrations/sqlite`).
pub static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

/// Postgres schema migrations (`migrations/postgres`).
pub static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");
