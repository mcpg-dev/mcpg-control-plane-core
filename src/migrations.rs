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

#[cfg(test)]
mod tests {
    use super::POSTGRES_MIGRATOR;
    use crate::model::{ORG_STATUS_ACTIVE, ORG_STATUS_DECOMMISSIONING, ORG_STATUS_SUSPENDED};

    /// Only Postgres puts a CHECK on `orgs.status` (Sqlite leaves the values
    /// to the repo), so a status the Sqlite suites write freely can be one
    /// Postgres refuses: the newest statement that sets the check must allow
    /// every status the control plane writes.
    #[test]
    fn the_postgres_org_status_check_allows_every_org_status() {
        let check = POSTGRES_MIGRATOR
            .iter()
            .flat_map(|m| {
                let code: Vec<&str> = m
                    .sql
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("--"))
                    .collect();
                code.join("\n")
                    .split(';')
                    .map(|stmt| stmt.split_whitespace().collect::<Vec<_>>().join(" "))
                    .collect::<Vec<_>>()
            })
            .rfind(|stmt| stmt.starts_with("ALTER TABLE orgs") && stmt.contains("CHECK (status IN"))
            .expect("a migration puts a CHECK on orgs.status");
        for status in [
            ORG_STATUS_ACTIVE,
            ORG_STATUS_SUSPENDED,
            ORG_STATUS_DECOMMISSIONING,
        ] {
            assert!(
                check.contains(&format!("'{status}'")),
                "the orgs.status check refuses `{status}`: {check}"
            );
        }
    }
}
