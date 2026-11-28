use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::http::StatusCode;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Clone, Copy, Debug)]
pub struct Error(pub StatusCode, pub &'static str);

pub type Result<T> = std::result::Result<T, Error>;

pub const INTERNAL: Error = Error(
    StatusCode::INTERNAL_SERVER_ERROR,
    "Local state operation failed.",
);
pub const UNAUTHORIZED: Error = Error(StatusCode::UNAUTHORIZED, "Sign in to continue.");
const INVALID_LOGIN: Error = Error(StatusCode::UNAUTHORIZED, "Email or password is incorrect.");
const FORBIDDEN: Error = Error(StatusCode::FORBIDDEN, "Administrator access is required.");
const CHANGE_REQUIRED: Error = Error(
    StatusCode::FORBIDDEN,
    "Change your temporary password first.",
);

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        if let rusqlite::Error::SqliteFailure(code, _) = error {
            eprintln!("AgentLink database error: {:?}", code.code);
        }
        INTERNAL
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Member,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }
}

#[derive(Serialize)]
pub struct User {
    pub id: i64,
    email: String,
    pub role: Role,
    pub active: bool,
    pub must_change: bool,
}

#[derive(Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct NewUser {
    pub email: String,
    pub password: String,
    pub role: Role,
}

#[derive(Deserialize)]
pub struct PasswordChange {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AccessChange {
    Disable,
    Enable { password: String },
    RevokeSessions,
    ResetPassword { password: String },
}

pub fn open(path: &Path, create: bool) -> Result<Connection> {
    let mut flags = OpenFlags::default();
    flags.set(OpenFlags::SQLITE_OPEN_CREATE, create);
    let db = Connection::open_with_flags(path, flags)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    db.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS users (
             id INTEGER PRIMARY KEY,
             email TEXT NOT NULL UNIQUE,
             password_hash TEXT NOT NULL,
             role TEXT NOT NULL CHECK(role IN ('admin', 'member')),
             active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
             must_change INTEGER NOT NULL CHECK(must_change IN (0, 1))
         );
         CREATE TABLE IF NOT EXISTS sessions (
             digest BLOB PRIMARY KEY,
             user_id INTEGER NOT NULL REFERENCES users(id),
             expires_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
         CREATE TABLE IF NOT EXISTS account_events (
             id INTEGER PRIMARY KEY,
             occurred_at INTEGER NOT NULL DEFAULT (unixepoch()),
             actor_id INTEGER NOT NULL REFERENCES users(id),
             subject_id INTEGER NOT NULL REFERENCES users(id),
             action TEXT NOT NULL
         );",
    )?;
    Ok(db)
}

pub fn initialized(db: &Connection) -> Result<bool> {
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM users)", [], |row| row.get(0))?)
}

pub fn bootstrap(db: &mut Connection, email: &str, password: &str) -> Result<bool> {
    let tx = write(db)?;
    if initialized(&tx)? {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO users (email, password_hash, role, must_change) VALUES (?1, ?2, 'admin', 1)",
        params![normalize_email(email)?, hash_password(password)?],
    )?;
    let id = tx.last_insert_rowid();
    audit(&tx, id, id, "bootstrap")?;
    tx.commit()?;
    Ok(true)
}

pub fn normalize_email(email: &str) -> Result<String> {
    let email = email.trim();
    if email.len() <= 254
        && email.is_ascii()
        && !email
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && !domain.contains('@')
        })
    {
        return Ok(email.to_ascii_lowercase());
    }
    Err(Error(
        StatusCode::BAD_REQUEST,
        "Enter a valid email address.",
    ))
}

pub fn validate_password(password: &str) -> Result<()> {
    if (12..=256).contains(&password.len()) && !password.chars().any(char::is_control) {
        return Ok(());
    }
    Err(Error(
        StatusCode::BAD_REQUEST,
        "Use a password of 12–256 bytes without control characters.",
    ))
}

pub fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| INTERNAL)?;
    Ok(hex::encode(bytes))
}

fn hash_password(password: &str) -> Result<String> {
    validate_password(password)?;
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|_| INTERNAL)?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| INTERNAL)?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| INTERNAL)?
        .to_string())
}

pub fn dummy_hash() -> Result<String> {
    hash_password(&random_token()?)
}

fn verify(password: &str, encoded: &str) -> Result<bool> {
    let hash = PasswordHash::new(encoded).map_err(|_| INTERNAL)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok())
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn write(db: &mut Connection) -> Result<Transaction<'_>> {
    Ok(db.transaction_with_behavior(TransactionBehavior::Immediate)?)
}

fn audit(db: &Connection, actor: i64, subject: i64, action: &str) -> Result<()> {
    db.execute(
        "INSERT INTO account_events (actor_id, subject_id, action) VALUES (?1, ?2, ?3)",
        params![actor, subject, action],
    )?;
    Ok(())
}

fn read_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        email: row.get(1)?,
        role: match row.get::<_, String>(2)?.as_str() {
            "admin" => Role::Admin,
            _ => Role::Member,
        },
        active: row.get(3)?,
        must_change: row.get(4)?,
    })
}

pub fn sign_in(db: &mut Connection, input: Credentials, dummy: &str) -> Result<String> {
    let email = normalize_email(&input.email).map_err(|_| INVALID_LOGIN)?;
    validate_password(&input.password).map_err(|_| INVALID_LOGIN)?;
    let tx = write(db)?;
    let account: Option<(i64, String, bool)> = tx
        .query_row(
            "SELECT id, password_hash, active FROM users WHERE email = ?1",
            [email],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let hash = account.as_ref().map_or(dummy, |(_, hash, _)| hash);
    let valid = verify(&input.password, hash)?;
    let Some((id, _, true)) = account.filter(|_| valid) else {
        return Err(INVALID_LOGIN);
    };
    tx.execute("DELETE FROM sessions WHERE expires_at <= unixepoch()", [])?;
    let token = random_token()?;
    tx.execute(
        "INSERT INTO sessions (digest, user_id, expires_at) VALUES (?1, ?2, unixepoch() + 43200)",
        params![digest(&token).as_slice(), id],
    )?;
    tx.commit()?;
    Ok(token)
}

pub fn current_user(db: &Connection, token: &str) -> Result<User> {
    db.query_row(
        "SELECT u.id, u.email, u.role, u.active, u.must_change
         FROM users u JOIN sessions s ON s.user_id = u.id
         WHERE s.digest = ?1 AND s.expires_at > unixepoch() AND u.active = 1",
        [digest(token).as_slice()],
        read_user,
    )
    .optional()?
    .ok_or(UNAUTHORIZED)
}

pub(crate) fn admin(db: &Connection, token: &str) -> Result<User> {
    let user = current_user(db, token)?;
    if user.role != Role::Admin {
        return Err(FORBIDDEN);
    }
    if user.must_change {
        return Err(CHANGE_REQUIRED);
    }
    Ok(user)
}

pub fn sign_out(db: &Connection, token: &str) -> Result<()> {
    db.execute(
        "DELETE FROM sessions WHERE digest = ?1",
        [digest(token).as_slice()],
    )?;
    Ok(())
}

fn revoke(db: &Connection, id: i64) -> Result<()> {
    db.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
    Ok(())
}

pub fn change_password(db: &mut Connection, token: &str, input: PasswordChange) -> Result<()> {
    let tx = write(db)?;
    let user = current_user(&tx, token)?;
    validate_password(&input.current_password)?;
    let hash: String = tx.query_row(
        "SELECT password_hash FROM users WHERE id = ?1",
        [user.id],
        |r| r.get(0),
    )?;
    if !verify(&input.current_password, &hash)? {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Current password is incorrect.",
        ));
    }
    if input.current_password == input.new_password {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Choose a different password.",
        ));
    }
    tx.execute(
        "UPDATE users SET password_hash = ?1, must_change = 0 WHERE id = ?2",
        params![hash_password(&input.new_password)?, user.id],
    )?;
    revoke(&tx, user.id)?;
    audit(&tx, user.id, user.id, "change_password")?;
    tx.commit()?;
    Ok(())
}

pub fn people(db: &Connection, token: &str) -> Result<Vec<User>> {
    admin(db, token)?;
    let mut query =
        db.prepare("SELECT id, email, role, active, must_change FROM users ORDER BY email")?;
    Ok(query
        .query_map([], read_user)?
        .collect::<rusqlite::Result<_>>()?)
}

pub fn add_user(db: &mut Connection, token: &str, input: NewUser) -> Result<User> {
    let tx = write(db)?;
    let actor = admin(&tx, token)?;
    let email = normalize_email(&input.email)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?1)",
        [&email],
        |r| r.get(0),
    )?;
    if exists {
        return Err(Error(
            StatusCode::CONFLICT,
            "This email already has an account.",
        ));
    }
    tx.execute(
        "INSERT INTO users (email, password_hash, role, must_change) VALUES (?1, ?2, ?3, 1)",
        params![email, hash_password(&input.password)?, input.role.as_str()],
    )?;
    let id = tx.last_insert_rowid();
    audit(&tx, actor.id, id, "add_user")?;
    tx.commit()?;
    Ok(User {
        id,
        email,
        role: input.role,
        active: true,
        must_change: true,
    })
}

fn set_temporary_password(db: &Connection, id: i64, password: &str) -> Result<()> {
    validate_password(password)?;
    let existing: String = db.query_row(
        "SELECT password_hash FROM users WHERE id = ?1",
        [id],
        |row| row.get(0),
    )?;
    if verify(password, &existing)? {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Choose a different temporary password.",
        ));
    }
    db.execute(
        "UPDATE users SET password_hash = ?1, must_change = 1 WHERE id = ?2",
        params![hash_password(password)?, id],
    )?;
    Ok(())
}

pub fn recovery_admin(db: &Connection, email: &str) -> Result<i64> {
    db.query_row(
        "SELECT id FROM users WHERE email = ?1 AND role = 'admin' AND active = 1",
        [normalize_email(email)?],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(Error(
        StatusCode::NOT_FOUND,
        "No active administrator has that email.",
    ))
}

pub fn reset_admin(db: &mut Connection, email: &str, password: &str) -> Result<()> {
    let tx = write(db)?;
    let id = recovery_admin(&tx, email)?;
    set_temporary_password(&tx, id, password)?;
    revoke(&tx, id)?;
    // The terminal operator has no account ID. This action identifies the
    // recovered account and distinguishes terminal recovery from an IAM reset.
    audit(&tx, id, id, "local_admin_recovery")?;
    tx.commit()?;
    Ok(())
}

pub fn change_access(
    db: &mut Connection,
    token: &str,
    id: i64,
    change: AccessChange,
) -> Result<()> {
    let tx = write(db)?;
    let actor = admin(&tx, token)?;
    let (role, active): (String, bool) = tx
        .query_row("SELECT role, active FROM users WHERE id = ?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?
        .ok_or(Error(StatusCode::NOT_FOUND, "Account not found."))?;
    if !active && !matches!(change, AccessChange::Enable { .. }) {
        return Err(Error(
            StatusCode::CONFLICT,
            "This account is already disabled.",
        ));
    }
    let action = match change {
        AccessChange::Disable => {
            if role == "admin" {
                let admins: i64 = tx.query_row(
                    "SELECT count(*) FROM users WHERE role = 'admin' AND active = 1",
                    [],
                    |r| r.get(0),
                )?;
                if admins == 1 {
                    return Err(Error(
                        StatusCode::CONFLICT,
                        "The last active administrator cannot be disabled.",
                    ));
                }
            }
            tx.execute("UPDATE users SET active = 0 WHERE id = ?1", [id])?;
            "disable"
        }
        AccessChange::RevokeSessions => "revoke_sessions",
        AccessChange::Enable { password } => {
            if active {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "This account already has access.",
                ));
            }
            set_temporary_password(&tx, id, &password)?;
            tx.execute("UPDATE users SET active = 1 WHERE id = ?1", [id])?;
            "enable"
        }
        AccessChange::ResetPassword { password } => {
            set_temporary_password(&tx, id, &password)?;
            "reset_password"
        }
    };
    revoke(&tx, id)?;
    audit(&tx, actor.id, id, action)?;
    tx.commit()?;
    Ok(())
}
