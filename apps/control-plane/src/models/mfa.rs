use rusqlite::{params, Connection};
use shared::dto::auth::{MfaFactorKind, MfaFactorStatus};
use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};

const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS mfa_factors (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('totp', 'web_authn')),
    label TEXT,
    secret_ciphertext BLOB,
    credential_id BLOB,
    credential_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    enrolled_at TEXT,
    last_used_at TEXT,
    disabled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_mfa_factors_active_user_kind
    ON mfa_factors(user_id, kind)
    WHERE enrolled_at IS NOT NULL AND disabled_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_factors_active_credential_id
    ON mfa_factors(credential_id)
    WHERE credential_id IS NOT NULL AND disabled_at IS NULL;
"#;

#[derive(Clone)]
pub struct MfaStore {
    conn: Option<Arc<Mutex<Connection>>>,
}

impl MfaStore {
    pub fn disabled() -> Self {
        Self { conn: None }
    }

    pub fn from_optional_database_url(url: Option<&str>) -> anyhow::Result<Self> {
        match url {
            Some(url) => Self::from_database_url(url),
            None => Ok(Self::disabled()),
        }
    }

    pub fn from_database_url(url: &str) -> anyhow::Result<Self> {
        let path = sqlite_path_from_url(url)?;
        let conn = Connection::open(path)?;
        conn.execute_batch(SQLITE_SCHEMA)?;
        Ok(Self {
            conn: Some(Arc::new(Mutex::new(conn))),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.conn.is_some()
    }

    pub fn factor_statuses(&self, user_id: &str) -> anyhow::Result<Vec<MfaFactorStatus>> {
        let Some(conn) = self.connection()? else {
            return Ok(default_factor_statuses(false, &HashSet::new()));
        };

        let mut stmt = conn.prepare(
            "SELECT DISTINCT kind
             FROM mfa_factors
             WHERE user_id = ?1
               AND enrolled_at IS NOT NULL
               AND disabled_at IS NULL",
        )?;
        let rows = stmt.query_map(params![user_id], |row| row.get::<_, String>(0))?;
        let enrolled = rows.collect::<rusqlite::Result<HashSet<_>>>()?;

        Ok(default_factor_statuses(true, &enrolled))
    }

    fn connection(&self) -> anyhow::Result<Option<MutexGuard<'_, Connection>>> {
        self.conn
            .as_ref()
            .map(|conn| {
                conn.lock()
                    .map_err(|_| anyhow::anyhow!("MFA store connection lock poisoned"))
            })
            .transpose()
    }
}

fn default_factor_statuses(
    available: bool,
    enrolled_kinds: &HashSet<String>,
) -> Vec<MfaFactorStatus> {
    [MfaFactorKind::Totp, MfaFactorKind::WebAuthn]
        .into_iter()
        .map(|kind| MfaFactorStatus {
            kind,
            available,
            enrolled: enrolled_kinds.contains(kind_code(kind)),
            label: Some(kind_label(kind).into()),
        })
        .collect()
}

fn kind_code(kind: MfaFactorKind) -> &'static str {
    match kind {
        MfaFactorKind::Totp => "totp",
        MfaFactorKind::WebAuthn => "web_authn",
    }
}

fn kind_label(kind: MfaFactorKind) -> &'static str {
    match kind {
        MfaFactorKind::Totp => "Authenticator app",
        MfaFactorKind::WebAuthn => "Security key",
    }
}

fn sqlite_path_from_url(url: &str) -> anyhow::Result<String> {
    if url == "sqlite::memory:" || url == "sqlite://:memory:" {
        return Ok(":memory:".into());
    }

    let path = if let Some(path) = url.strip_prefix("sqlite://") {
        path
    } else if let Some(path) = url.strip_prefix("sqlite:") {
        path
    } else {
        anyhow::bail!("Only sqlite MFA database URLs are supported");
    };

    if path.is_empty() {
        anyhow::bail!("SQLite MFA database URL must include a path");
    }

    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_store_reports_unavailable_factors() {
        let statuses = MfaStore::disabled().factor_statuses("u1").unwrap();

        assert_eq!(statuses.len(), 2);
        assert!(statuses.iter().all(|factor| !factor.available));
        assert!(statuses.iter().all(|factor| !factor.enrolled));
    }

    #[test]
    fn enabled_store_reports_available_unenrolled_factors() {
        let store = MfaStore::from_database_url("sqlite::memory:").unwrap();
        let statuses = store.factor_statuses("u1").unwrap();

        assert!(statuses.iter().all(|factor| factor.available));
        assert!(statuses.iter().all(|factor| !factor.enrolled));
    }

    #[test]
    fn enrolled_active_factors_are_reported_by_user_and_kind() {
        let store = MfaStore::from_database_url("sqlite::memory:").unwrap();
        {
            let conn = store.connection().unwrap().unwrap();
            conn.execute(
                "INSERT INTO mfa_factors (id, user_id, kind, label, enrolled_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params!["factor-1", "u1", "totp", "Phone", "2026-01-01T00:00:00Z"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO mfa_factors (id, user_id, kind, label, enrolled_at, disabled_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    "factor-2",
                    "u1",
                    "web_authn",
                    "Old key",
                    "2026-01-01T00:00:00Z",
                    "2026-01-02T00:00:00Z"
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO mfa_factors (id, user_id, kind, label, enrolled_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    "factor-3",
                    "u2",
                    "web_authn",
                    "Other key",
                    "2026-01-01T00:00:00Z"
                ],
            )
            .unwrap();
        }

        let statuses = store.factor_statuses("u1").unwrap();
        let totp = statuses
            .iter()
            .find(|factor| factor.kind == MfaFactorKind::Totp)
            .unwrap();
        let webauthn = statuses
            .iter()
            .find(|factor| factor.kind == MfaFactorKind::WebAuthn)
            .unwrap();

        assert!(totp.available);
        assert!(totp.enrolled);
        assert!(webauthn.available);
        assert!(!webauthn.enrolled);
    }
}
