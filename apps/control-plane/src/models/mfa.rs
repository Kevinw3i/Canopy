use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use shared::dto::auth::{MfaFactorKind, MfaFactorStatus, TotpEnrollStartResponse};
use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};
use totp_rs::{Algorithm, Secret, TOTP};

const TOTP_ISSUER: &str = "Canopy";
const TOTP_DIGITS: usize = 6;
const TOTP_SKEW: u8 = 1;
const TOTP_STEP_SECONDS: u64 = 30;
const TOTP_PENDING_TTL_SQL: &str = "-10 minutes";
const RECOVERY_CODE_COUNT: usize = 10;
// Schema fields are reserved for WebAuthn, but no ceremony is exposed yet.
const WEBAUTHN_ENROLLMENT_AVAILABLE: bool = false;

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
    last_totp_step INTEGER,
    disabled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_mfa_factors_active_user_kind
    ON mfa_factors(user_id, kind)
    WHERE enrolled_at IS NOT NULL AND disabled_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_mfa_factors_pending_user_kind
    ON mfa_factors(user_id, kind, created_at)
    WHERE enrolled_at IS NULL AND disabled_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_factors_active_credential_id
    ON mfa_factors(credential_id)
    WHERE credential_id IS NOT NULL AND disabled_at IS NULL;

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    salt TEXT NOT NULL,
    code_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at TEXT,
    disabled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_active_user
    ON mfa_recovery_codes(user_id)
    WHERE used_at IS NULL AND disabled_at IS NULL;
"#;

#[derive(Debug, thiserror::Error)]
pub enum MfaStoreError {
    #[error("local MFA factor store is not configured")]
    StoreUnavailable,
    #[error("local TOTP enrollment requires mfa_secret_key")]
    TotpSecretKeyUnavailable,
    #[error("an active TOTP factor is already enrolled")]
    TotpAlreadyEnrolled,
    #[error("TOTP enrollment was not found or has expired")]
    TotpEnrollmentNotFound,
    #[error("TOTP code is invalid")]
    InvalidTotpCode,
    #[error("no active TOTP factor is enrolled")]
    NoActiveTotpFactor,
    #[error("TOTP code has already been used for this time step")]
    TotpCodeReplayed,
    #[error("local recovery codes require an active TOTP factor")]
    RecoveryCodesRequireTotp,
    #[error("recovery code is invalid or already used")]
    InvalidRecoveryCode,
    #[error("MFA secret key must be base64-encoded 32 bytes")]
    InvalidSecretKey,
    #[error("MFA secret envelope is invalid")]
    InvalidSecretEnvelope,
    #[error("MFA secret encryption failed")]
    SecretEncryptionFailed,
    #[error("MFA secret decryption failed")]
    SecretDecryptionFailed,
    #[error("MFA store connection lock poisoned")]
    LockPoisoned,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    SecretParse(#[from] totp_rs::SecretParseError),
    #[error(transparent)]
    TotpUrl(#[from] totp_rs::TotpUrlError),
    #[error(transparent)]
    Time(#[from] std::time::SystemTimeError),
}

type MfaResult<T> = Result<T, MfaStoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpVerifyResult {
    pub factor_id: String,
    pub matched_step: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCodesResult {
    pub codes: Vec<String>,
    pub remaining_codes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCodeVerifyResult {
    pub remaining_codes: usize,
}

#[derive(Clone)]
pub struct MfaStore {
    conn: Option<Arc<Mutex<Connection>>>,
    secret_key: Option<[u8; 32]>,
}

impl MfaStore {
    pub fn disabled() -> Self {
        Self {
            conn: None,
            secret_key: None,
        }
    }

    pub fn from_optional_config(
        database_url: Option<&str>,
        secret_key: Option<&str>,
    ) -> MfaResult<Self> {
        match database_url {
            Some(url) => Self::from_database_url_and_secret_key(url, secret_key),
            None => {
                if secret_key.is_some() {
                    parse_secret_key(secret_key)?;
                }
                Ok(Self::disabled())
            }
        }
    }

    pub fn from_optional_database_url(url: Option<&str>) -> anyhow::Result<Self> {
        Self::from_optional_config(url, None).map_err(anyhow::Error::from)
    }

    pub fn from_database_url(url: &str) -> anyhow::Result<Self> {
        Self::from_database_url_and_secret_key(url, None).map_err(anyhow::Error::from)
    }

    pub fn from_database_url_and_secret_key(
        url: &str,
        secret_key: Option<&str>,
    ) -> MfaResult<Self> {
        let path = sqlite_path_from_url(url)?;
        let conn = Connection::open(path)?;
        ensure_sqlite_schema(&conn)?;
        Ok(Self {
            conn: Some(Arc::new(Mutex::new(conn))),
            secret_key: parse_secret_key(secret_key)?,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.conn.is_some()
    }

    pub fn totp_enrollment_available(&self) -> bool {
        self.conn.is_some() && self.secret_key.is_some()
    }

    pub fn factor_statuses(&self, user_id: &str) -> MfaResult<Vec<MfaFactorStatus>> {
        let Some(conn) = self.connection()? else {
            return Ok(default_factor_statuses(false, false, &HashSet::new()));
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

        Ok(default_factor_statuses(
            self.totp_enrollment_available(),
            WEBAUTHN_ENROLLMENT_AVAILABLE,
            &enrolled,
        ))
    }

    pub fn start_totp_enrollment(
        &self,
        user_id: &str,
        account_name: &str,
        label: Option<&str>,
    ) -> MfaResult<TotpEnrollStartResponse> {
        let mut conn = self.required_connection()?;
        let secret_key = self
            .secret_key
            .ok_or(MfaStoreError::TotpSecretKeyUnavailable)?;

        let active_count: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM mfa_factors
             WHERE user_id = ?1
               AND kind = 'totp'
               AND enrolled_at IS NOT NULL
               AND disabled_at IS NULL",
            params![user_id],
            |row| row.get(0),
        )?;
        if active_count > 0 {
            return Err(MfaStoreError::TotpAlreadyEnrolled);
        }

        let factor_id = uuid::Uuid::new_v4().to_string();
        let secret = Secret::generate_secret();
        let secret_base32 = secret.to_encoded().to_string();
        let secret_bytes = secret.to_bytes()?;
        let safe_account_name = safe_totp_account_name(account_name, user_id);
        let totp = build_totp(secret_bytes.clone(), &safe_account_name)?;
        let otpauth_url = totp.get_url();
        let aad = secret_aad(user_id, &factor_id);
        let secret_ciphertext = encrypt_secret(&secret_key, &aad, &secret_bytes)?;
        let label = normalized_label(label);

        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM mfa_factors
             WHERE user_id = ?1
               AND kind = 'totp'
               AND enrolled_at IS NULL",
            params![user_id],
        )?;
        tx.execute(
            "INSERT INTO mfa_factors (id, user_id, kind, label, secret_ciphertext)
             VALUES (?1, ?2, 'totp', ?3, ?4)",
            params![factor_id, user_id, label, secret_ciphertext],
        )?;
        tx.commit()?;

        Ok(TotpEnrollStartResponse {
            factor_id,
            secret_base32,
            otpauth_url,
            issuer: TOTP_ISSUER.into(),
            account_name: safe_account_name,
        })
    }

    pub fn confirm_totp_enrollment(
        &self,
        user_id: &str,
        factor_id: &str,
        code: &str,
    ) -> MfaResult<()> {
        let mut conn = self.required_connection()?;
        let secret_key = self
            .secret_key
            .ok_or(MfaStoreError::TotpSecretKeyUnavailable)?;
        let code = normalized_totp_code(code)?;
        let aad = secret_aad(user_id, factor_id);

        let tx = conn.transaction()?;
        let secret_ciphertext: Vec<u8> = tx
            .query_row(
                "SELECT secret_ciphertext
                 FROM mfa_factors
                 WHERE id = ?1
                   AND user_id = ?2
                   AND kind = 'totp'
                   AND enrolled_at IS NULL
                   AND disabled_at IS NULL
                   AND datetime(created_at) >= datetime('now', ?3)",
                params![factor_id, user_id, TOTP_PENDING_TTL_SQL],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(MfaStoreError::TotpEnrollmentNotFound)?;

        let secret_bytes = decrypt_secret(&secret_key, &aad, &secret_ciphertext)?;
        let totp = build_totp(secret_bytes, &safe_totp_account_name(user_id, user_id))?;
        if !totp.check_current(&code)? {
            return Err(MfaStoreError::InvalidTotpCode);
        }

        tx.execute(
            "UPDATE mfa_factors
             SET enrolled_at = CURRENT_TIMESTAMP
             WHERE id = ?1
               AND user_id = ?2
               AND kind = 'totp'
               AND enrolled_at IS NULL
               AND disabled_at IS NULL",
            params![factor_id, user_id],
        )?;
        tx.commit()?;

        Ok(())
    }

    pub fn verify_totp(&self, user_id: &str, code: &str) -> MfaResult<TotpVerifyResult> {
        let conn = self.required_connection()?;
        let secret_key = self
            .secret_key
            .ok_or(MfaStoreError::TotpSecretKeyUnavailable)?;
        let code = normalized_totp_code(code)?;
        let now = current_unix_seconds()?;

        let mut stmt = conn.prepare(
            "SELECT id, secret_ciphertext, last_totp_step
             FROM mfa_factors
             WHERE user_id = ?1
               AND kind = 'totp'
               AND enrolled_at IS NOT NULL
               AND disabled_at IS NULL",
        )?;
        let rows = stmt.query_map(params![user_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })?;
        let factors = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if factors.is_empty() {
            return Err(MfaStoreError::NoActiveTotpFactor);
        }

        for (factor_id, secret_ciphertext, last_totp_step) in factors {
            let aad = secret_aad(user_id, &factor_id);
            let secret_bytes = decrypt_secret(&secret_key, &aad, &secret_ciphertext)?;
            let totp = build_totp(secret_bytes, &safe_totp_account_name(user_id, user_id))?;
            let Some(matched_step) = matching_totp_step(&totp, &code, now) else {
                continue;
            };

            if last_totp_step.is_some_and(|step| step >= matched_step as i64) {
                return Err(MfaStoreError::TotpCodeReplayed);
            }

            let updated = conn.execute(
                "UPDATE mfa_factors
                 SET last_used_at = CURRENT_TIMESTAMP,
                     last_totp_step = ?1
                 WHERE id = ?2
                   AND user_id = ?3
                   AND kind = 'totp'
                   AND enrolled_at IS NOT NULL
                   AND disabled_at IS NULL
                   AND (last_totp_step IS NULL OR last_totp_step < ?1)",
                params![matched_step as i64, factor_id, user_id],
            )?;
            if updated == 0 {
                return Err(MfaStoreError::TotpCodeReplayed);
            }

            return Ok(TotpVerifyResult {
                factor_id,
                matched_step,
            });
        }

        Err(MfaStoreError::InvalidTotpCode)
    }

    pub fn recovery_codes_remaining(&self, user_id: &str) -> MfaResult<Option<usize>> {
        let Some(conn) = self.connection()? else {
            return Ok(None);
        };

        let remaining: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM mfa_recovery_codes
             WHERE user_id = ?1
               AND used_at IS NULL
               AND disabled_at IS NULL",
            params![user_id],
            |row| row.get(0),
        )?;
        Ok(Some(remaining as usize))
    }

    pub fn generate_recovery_codes(&self, user_id: &str) -> MfaResult<RecoveryCodesResult> {
        let Some(result) = self.generate_recovery_codes_with_precommit(user_id, |_| true)? else {
            unreachable!("recovery code generation precommit returned false")
        };
        Ok(result)
    }

    pub(crate) fn generate_recovery_codes_with_precommit<F>(
        &self,
        user_id: &str,
        precommit: F,
    ) -> MfaResult<Option<RecoveryCodesResult>>
    where
        F: FnOnce(&[String]) -> bool,
    {
        let mut conn = self.required_connection()?;
        let active_totp_exists: i64 = conn.query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM mfa_factors
                 WHERE user_id = ?1
                   AND kind = 'totp'
                   AND enrolled_at IS NOT NULL
                   AND disabled_at IS NULL
             )",
            params![user_id],
            |row| row.get(0),
        )?;
        if active_totp_exists == 0 {
            return Err(MfaStoreError::RecoveryCodesRequireTotp);
        }

        let codes = (0..RECOVERY_CODE_COUNT)
            .map(|_| generate_recovery_code())
            .collect::<Vec<_>>();

        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE mfa_recovery_codes
             SET disabled_at = CURRENT_TIMESTAMP
             WHERE user_id = ?1
               AND used_at IS NULL
               AND disabled_at IS NULL",
            params![user_id],
        )?;
        for code in &codes {
            let salt = generate_recovery_salt();
            let code_hash = recovery_code_hash(&salt, code);
            tx.execute(
                "INSERT INTO mfa_recovery_codes (id, user_id, salt, code_hash)
                 VALUES (?1, ?2, ?3, ?4)",
                params![uuid::Uuid::new_v4().to_string(), user_id, salt, code_hash],
            )?;
        }
        if !precommit(&codes) {
            return Ok(None);
        }
        tx.commit()?;

        Ok(Some(RecoveryCodesResult {
            remaining_codes: codes.len(),
            codes,
        }))
    }

    pub fn verify_recovery_code(
        &self,
        user_id: &str,
        code: &str,
    ) -> MfaResult<RecoveryCodeVerifyResult> {
        let Some(result) = self.verify_recovery_code_with_precommit(user_id, code, |_| true)?
        else {
            unreachable!("recovery code verification precommit returned false")
        };
        Ok(result)
    }

    pub(crate) fn verify_recovery_code_with_precommit<F>(
        &self,
        user_id: &str,
        code: &str,
        precommit: F,
    ) -> MfaResult<Option<RecoveryCodeVerifyResult>>
    where
        F: FnOnce(usize) -> bool,
    {
        let code = normalized_recovery_code(code)?;
        let mut conn = self.required_connection()?;
        let tx = conn.transaction()?;
        let matched_id = {
            let mut stmt = tx.prepare(
                "SELECT id, salt, code_hash
                 FROM mfa_recovery_codes
                 WHERE user_id = ?1
                   AND used_at IS NULL
                   AND disabled_at IS NULL",
            )?;
            let rows = stmt.query_map(params![user_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            let mut matched_id = None;
            for row in rows {
                let (id, salt, code_hash) = row?;
                if recovery_code_hash(&salt, &code) == code_hash {
                    matched_id = Some(id);
                    break;
                }
            }
            matched_id
        };
        let Some(matched_id) = matched_id else {
            return Err(MfaStoreError::InvalidRecoveryCode);
        };

        let updated = tx.execute(
            "UPDATE mfa_recovery_codes
             SET used_at = CURRENT_TIMESTAMP
             WHERE id = ?1
               AND user_id = ?2
               AND used_at IS NULL
               AND disabled_at IS NULL",
            params![matched_id, user_id],
        )?;
        if updated == 0 {
            return Err(MfaStoreError::InvalidRecoveryCode);
        }

        let remaining: i64 = tx.query_row(
            "SELECT COUNT(*)
             FROM mfa_recovery_codes
             WHERE user_id = ?1
               AND used_at IS NULL
               AND disabled_at IS NULL",
            params![user_id],
            |row| row.get(0),
        )?;
        let remaining_codes = remaining as usize;
        if !precommit(remaining_codes) {
            return Ok(None);
        }
        tx.commit()?;

        Ok(Some(RecoveryCodeVerifyResult { remaining_codes }))
    }

    fn connection(&self) -> MfaResult<Option<MutexGuard<'_, Connection>>> {
        self.conn
            .as_ref()
            .map(|conn| conn.lock().map_err(|_| MfaStoreError::LockPoisoned))
            .transpose()
    }

    fn required_connection(&self) -> MfaResult<MutexGuard<'_, Connection>> {
        self.connection()?.ok_or(MfaStoreError::StoreUnavailable)
    }
}

fn default_factor_statuses(
    totp_available: bool,
    webauthn_available: bool,
    enrolled_kinds: &HashSet<String>,
) -> Vec<MfaFactorStatus> {
    [MfaFactorKind::Totp, MfaFactorKind::WebAuthn]
        .into_iter()
        .map(|kind| MfaFactorStatus {
            kind,
            available: match kind {
                MfaFactorKind::Totp => totp_available,
                MfaFactorKind::WebAuthn => webauthn_available,
            },
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

fn ensure_sqlite_schema(conn: &Connection) -> MfaResult<()> {
    conn.execute_batch(SQLITE_SCHEMA)?;
    ensure_column(conn, "mfa_factors", "last_totp_step", "INTEGER")?;
    Ok(())
}

fn ensure_column(conn: &Connection, table: &str, column: &str, column_type: &str) -> MfaResult<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<HashSet<_>>>()?;
    if !columns.contains(column) {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {column_type}"),
            [],
        )?;
    }
    Ok(())
}

fn sqlite_path_from_url(url: &str) -> MfaResult<String> {
    if url == "sqlite::memory:" || url == "sqlite://:memory:" {
        return Ok(":memory:".into());
    }

    let path = if let Some(path) = url.strip_prefix("sqlite://") {
        path
    } else if let Some(path) = url.strip_prefix("sqlite:") {
        path
    } else {
        return Err(MfaStoreError::StoreUnavailable);
    };

    if path.is_empty() {
        return Err(MfaStoreError::StoreUnavailable);
    }

    Ok(path.to_string())
}

fn parse_secret_key(value: Option<&str>) -> MfaResult<Option<[u8; 32]>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let decoded = STANDARD
        .decode(value)
        .map_err(|_| MfaStoreError::InvalidSecretKey)?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| MfaStoreError::InvalidSecretKey)?;
    Ok(Some(key))
}

fn encrypt_secret(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> MfaResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| MfaStoreError::SecretEncryptionFailed)?;

    let mut envelope = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    envelope.push(1);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn decrypt_secret(key: &[u8; 32], aad: &[u8], envelope: &[u8]) -> MfaResult<Vec<u8>> {
    if envelope.len() <= 25 || envelope[0] != 1 {
        return Err(MfaStoreError::InvalidSecretEnvelope);
    }

    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&envelope[1..25]);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &envelope[25..],
                aad,
            },
        )
        .map_err(|_| MfaStoreError::SecretDecryptionFailed)
}

fn secret_aad(user_id: &str, factor_id: &str) -> Vec<u8> {
    format!("canopy:mfa:totp:{user_id}:{factor_id}").into_bytes()
}

fn normalized_label(label: Option<&str>) -> String {
    label
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .unwrap_or("Authenticator app")
        .chars()
        .take(80)
        .collect()
}

fn safe_totp_account_name(account_name: &str, fallback: &str) -> String {
    let account_name = account_name.trim();
    let source = if account_name.is_empty() {
        fallback.trim()
    } else {
        account_name
    };
    let sanitized: String = source
        .chars()
        .map(|ch| if ch == ':' { '_' } else { ch })
        .take(120)
        .collect();
    if sanitized.is_empty() {
        "user".into()
    } else {
        sanitized
    }
}

fn normalized_totp_code(code: &str) -> MfaResult<String> {
    let code = code.trim().replace(' ', "");
    if code.len() != TOTP_DIGITS || !code.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(MfaStoreError::InvalidTotpCode);
    }
    Ok(code)
}

fn generate_recovery_code() -> String {
    let mut bytes = [0u8; 10];
    OsRng.fill_bytes(&mut bytes);
    let encoded = hex::encode_upper(bytes);
    [
        &encoded[0..4],
        &encoded[4..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
    ]
    .join("-")
}

fn generate_recovery_salt() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn normalized_recovery_code(code: &str) -> MfaResult<String> {
    let compact = code
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '-')
        .map(|ch| ch.to_ascii_uppercase())
        .collect::<String>();
    if compact.len() != 20 || !compact.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(MfaStoreError::InvalidRecoveryCode);
    }
    Ok([
        &compact[0..4],
        &compact[4..8],
        &compact[8..12],
        &compact[12..16],
        &compact[16..20],
    ]
    .join("-"))
}

fn recovery_code_hash(salt: &str, code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

fn build_totp(secret: Vec<u8>, account_name: &str) -> MfaResult<TOTP> {
    Ok(TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP_SECONDS,
        secret,
        Some(TOTP_ISSUER.into()),
        account_name.into(),
    )?)
}

fn current_unix_seconds() -> MfaResult<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn matching_totp_step(totp: &TOTP, code: &str, now: u64) -> Option<u64> {
    let current_step = now / TOTP_STEP_SECONDS;
    let first_step = current_step.saturating_sub(TOTP_SKEW as u64);
    let last_step = current_step.saturating_add(TOTP_SKEW as u64);

    (first_step..=last_step).find(|step| {
        let step_time = step.saturating_mul(TOTP_STEP_SECONDS);
        totp.generate(step_time) == code
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn disabled_store_reports_unavailable_factors() {
        let statuses = MfaStore::disabled().factor_statuses("u1").unwrap();

        assert_eq!(statuses.len(), 2);
        assert!(statuses.iter().all(|factor| !factor.available));
        assert!(statuses.iter().all(|factor| !factor.enrolled));
    }

    #[test]
    fn enabled_store_without_secret_key_reports_totp_unavailable() {
        let store = MfaStore::from_database_url("sqlite::memory:").unwrap();
        let statuses = store.factor_statuses("u1").unwrap();

        let totp = statuses
            .iter()
            .find(|factor| factor.kind == MfaFactorKind::Totp)
            .unwrap();
        let webauthn = statuses
            .iter()
            .find(|factor| factor.kind == MfaFactorKind::WebAuthn)
            .unwrap();
        assert!(!totp.available);
        assert!(!webauthn.available);
        assert!(statuses.iter().all(|factor| !factor.enrolled));
    }

    #[test]
    fn enabled_store_with_secret_key_reports_totp_available() {
        let store =
            MfaStore::from_database_url_and_secret_key("sqlite::memory:", Some(TEST_KEY)).unwrap();
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
        assert!(!webauthn.available);
        assert!(statuses.iter().all(|factor| !factor.enrolled));
    }

    #[test]
    fn enrolled_active_factors_are_reported_by_user_and_kind() {
        let store =
            MfaStore::from_database_url_and_secret_key("sqlite::memory:", Some(TEST_KEY)).unwrap();
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
        assert!(!webauthn.available);
        assert!(!webauthn.enrolled);
    }

    #[test]
    fn totp_enrollment_roundtrip_encrypts_secret_and_enrolls() {
        let store =
            MfaStore::from_database_url_and_secret_key("sqlite::memory:", Some(TEST_KEY)).unwrap();
        let started = store
            .start_totp_enrollment("u1", "alice@example.com", Some("Phone"))
            .unwrap();
        assert_eq!(started.issuer, "Canopy");
        assert!(started.otpauth_url.starts_with("otpauth://totp/"));
        assert!(!started.secret_base32.is_empty());

        let encrypted: Vec<u8> = {
            let conn = store.connection().unwrap().unwrap();
            conn.query_row(
                "SELECT secret_ciphertext FROM mfa_factors WHERE id = ?1",
                params![started.factor_id],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert!(!encrypted
            .windows(started.secret_base32.len())
            .any(|window| { window == started.secret_base32.as_bytes() }));

        let secret = Secret::Encoded(started.secret_base32.clone())
            .to_bytes()
            .unwrap();
        let code = build_totp(secret, "alice@example.com")
            .unwrap()
            .generate_current()
            .unwrap();

        store
            .confirm_totp_enrollment("u1", &started.factor_id, &code)
            .unwrap();

        let statuses = store.factor_statuses("u1").unwrap();
        let totp = statuses
            .iter()
            .find(|factor| factor.kind == MfaFactorKind::Totp)
            .unwrap();
        assert!(totp.enrolled);
    }

    #[test]
    fn invalid_totp_code_does_not_enroll() {
        let store =
            MfaStore::from_database_url_and_secret_key("sqlite::memory:", Some(TEST_KEY)).unwrap();
        let started = store
            .start_totp_enrollment("u1", "alice@example.com", None)
            .unwrap();
        let secret = Secret::Encoded(started.secret_base32.clone())
            .to_bytes()
            .unwrap();
        let valid_code = build_totp(secret, "alice@example.com")
            .unwrap()
            .generate_current()
            .unwrap();
        let invalid_code = if valid_code == "000000" {
            "000001"
        } else {
            "000000"
        };

        let err = store
            .confirm_totp_enrollment("u1", &started.factor_id, invalid_code)
            .unwrap_err();

        assert!(matches!(err, MfaStoreError::InvalidTotpCode));
        let statuses = store.factor_statuses("u1").unwrap();
        let totp = statuses
            .iter()
            .find(|factor| factor.kind == MfaFactorKind::Totp)
            .unwrap();
        assert!(!totp.enrolled);
    }

    #[test]
    fn verify_totp_updates_last_used_and_rejects_replay() {
        let store =
            MfaStore::from_database_url_and_secret_key("sqlite::memory:", Some(TEST_KEY)).unwrap();
        let started = store
            .start_totp_enrollment("u1", "alice@example.com", None)
            .unwrap();
        let secret = Secret::Encoded(started.secret_base32.clone())
            .to_bytes()
            .unwrap();
        let code = build_totp(secret, "alice@example.com")
            .unwrap()
            .generate_current()
            .unwrap();

        store
            .confirm_totp_enrollment("u1", &started.factor_id, &code)
            .unwrap();
        let verified = store.verify_totp("u1", &code).unwrap();
        assert_eq!(verified.factor_id, started.factor_id);

        let (last_used_at, last_step): (Option<String>, Option<i64>) = {
            let conn = store.connection().unwrap().unwrap();
            conn.query_row(
                "SELECT last_used_at, last_totp_step FROM mfa_factors WHERE id = ?1",
                params![started.factor_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
        };
        assert!(last_used_at.is_some());
        assert_eq!(last_step, Some(verified.matched_step as i64));

        let err = store.verify_totp("u1", &code).unwrap_err();
        assert!(matches!(err, MfaStoreError::TotpCodeReplayed));
    }

    #[test]
    fn generate_recovery_codes_rotates_hashed_codes() {
        let store =
            MfaStore::from_database_url_and_secret_key("sqlite::memory:", Some(TEST_KEY)).unwrap();
        let started = store
            .start_totp_enrollment("u1", "alice@example.com", None)
            .unwrap();
        let secret = Secret::Encoded(started.secret_base32.clone())
            .to_bytes()
            .unwrap();
        let code = build_totp(secret, "alice@example.com")
            .unwrap()
            .generate_current()
            .unwrap();
        store
            .confirm_totp_enrollment("u1", &started.factor_id, &code)
            .unwrap();

        let generated = store.generate_recovery_codes("u1").unwrap();
        assert_eq!(generated.codes.len(), RECOVERY_CODE_COUNT);
        assert!(generated
            .codes
            .iter()
            .all(|code| code.len() == 24 && code.matches('-').count() == 4));
        assert_eq!(store.recovery_codes_remaining("u1").unwrap(), Some(10));

        let plaintext = generated.codes[0].clone();
        let conn = store.connection().unwrap().unwrap();
        let stored_plaintext_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM mfa_recovery_codes WHERE code_hash = ?1",
                params![plaintext],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_plaintext_count, 0);
        drop(conn);

        let verified = store
            .verify_recovery_code("u1", &generated.codes[0])
            .unwrap();
        assert_eq!(verified.remaining_codes, 9);
        assert_eq!(store.recovery_codes_remaining("u1").unwrap(), Some(9));
        let replay = store
            .verify_recovery_code("u1", &generated.codes[0])
            .unwrap_err();
        assert!(matches!(replay, MfaStoreError::InvalidRecoveryCode));

        let normalized_variant = generated.codes[1].to_ascii_lowercase().replace('-', " ");
        let verified = store
            .verify_recovery_code("u1", &normalized_variant)
            .unwrap();
        assert_eq!(verified.remaining_codes, 8);

        let rejected = store
            .verify_recovery_code_with_precommit("u1", &generated.codes[2], |_| false)
            .unwrap();
        assert!(rejected.is_none());
        assert_eq!(store.recovery_codes_remaining("u1").unwrap(), Some(8));

        let rejected = store
            .generate_recovery_codes_with_precommit("u1", |_| false)
            .unwrap();
        assert!(rejected.is_none());
        assert_eq!(store.recovery_codes_remaining("u1").unwrap(), Some(8));

        let rotated = store.generate_recovery_codes("u1").unwrap();
        assert_eq!(rotated.codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(store.recovery_codes_remaining("u1").unwrap(), Some(10));
    }

    #[test]
    fn generate_recovery_codes_requires_active_totp() {
        let store =
            MfaStore::from_database_url_and_secret_key("sqlite::memory:", Some(TEST_KEY)).unwrap();

        let err = store.generate_recovery_codes("u1").unwrap_err();

        assert!(matches!(err, MfaStoreError::RecoveryCodesRequireTotp));
    }

    #[test]
    fn invalid_recovery_code_format_is_rejected() {
        assert!(matches!(
            normalized_recovery_code("not-a-code"),
            Err(MfaStoreError::InvalidRecoveryCode)
        ));
        assert!(matches!(
            normalized_recovery_code("AAAA-BBBB-CCCC-DDDD-EEEZ"),
            Err(MfaStoreError::InvalidRecoveryCode)
        ));
    }

    #[test]
    fn schema_migration_adds_last_totp_step_column() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE mfa_factors (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                label TEXT,
                secret_ciphertext BLOB,
                credential_id BLOB,
                credential_json TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                enrolled_at TEXT,
                last_used_at TEXT,
                disabled_at TEXT
            );",
        )
        .unwrap();

        ensure_sqlite_schema(&conn).unwrap();

        let has_column: bool = conn
            .prepare("PRAGMA table_info(mfa_factors)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
            .iter()
            .any(|column| column == "last_totp_step");
        assert!(has_column);
    }
}
