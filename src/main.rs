mod iam;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use rusqlite::Connection;
use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, SocketAddrV4},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, sync::Semaphore};

const COOKIE: &str = "agentlink_session";

#[derive(Clone)]
struct App {
    db: Arc<Mutex<Connection>>,
    dummy_hash: Arc<str>,
    authority: Arc<str>,
    slots: Arc<Semaphore>,
}

impl IntoResponse for iam::Error {
    fn into_response(self) -> Response {
        (self.0, Json(ErrorMessage { error: self.1 })).into_response()
    }
}

#[derive(serde::Serialize)]
struct ErrorMessage {
    error: &'static str,
}

impl App {
    async fn query<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut Connection) -> iam::Result<T> + Send + 'static,
    ) -> iam::Result<T> {
        let permit = self.slots.clone().try_acquire_owned().map_err(|_| {
            iam::Error(
                StatusCode::SERVICE_UNAVAILABLE,
                "AgentLink is busy. Try again.",
            )
        })?;
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut db = db.lock().map_err(|_| iam::INTERNAL)?;
            work(&mut db)
        })
        .await
        .map_err(|_| iam::INTERNAL)?
    }
}

fn session(headers: &HeaderMap) -> iam::Result<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, value)| {
            *key == COOKIE && value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
        })
        .map(|(_, value)| value.to_owned())
        .ok_or(iam::UNAUTHORIZED)
}

fn session_reply(token: &str, max_age: u32) -> Response {
    let cookie = format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}");
    (StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response()
}

async fn sign_in(
    State(app): State<App>,
    Json(input): Json<iam::Credentials>,
) -> iam::Result<Response> {
    let dummy = app.dummy_hash.clone();
    let token = app.query(move |db| iam::sign_in(db, input, &dummy)).await?;
    Ok(session_reply(&token, 43200))
}

async fn sign_out(State(app): State<App>, headers: HeaderMap) -> iam::Result<Response> {
    if let Ok(token) = session(&headers) {
        app.query(move |db| iam::sign_out(db, &token)).await?;
    }
    Ok(session_reply("", 0))
}

async fn current_user(State(app): State<App>, headers: HeaderMap) -> iam::Result<Json<iam::User>> {
    let token = session(&headers)?;
    Ok(Json(
        app.query(move |db| iam::current_user(db, &token)).await?,
    ))
}

async fn change_password(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<iam::PasswordChange>,
) -> iam::Result<Response> {
    let token = session(&headers)?;
    app.query(move |db| iam::change_password(db, &token, input))
        .await?;
    Ok(session_reply("", 0))
}

async fn people(State(app): State<App>, headers: HeaderMap) -> iam::Result<Json<Vec<iam::User>>> {
    let token = session(&headers)?;
    Ok(Json(app.query(move |db| iam::people(db, &token)).await?))
}

async fn add_user(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<iam::NewUser>,
) -> iam::Result<(StatusCode, Json<iam::User>)> {
    let token = session(&headers)?;
    let user = app
        .query(move |db| iam::add_user(db, &token, input))
        .await?;
    Ok((StatusCode::CREATED, Json(user)))
}

async fn change_access(
    State(app): State<App>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(input): Json<iam::AccessChange>,
) -> iam::Result<StatusCode> {
    let token = session(&headers)?;
    app.query(move |db| iam::change_access(db, &token, id, input))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn local_only(State(app): State<App>, request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok());
    let origin = request.headers().get(header::ORIGIN);
    if host != Some(&app.authority)
        || origin.is_some_and(|v| v.as_bytes() != format!("http://{}", app.authority).as_bytes())
    {
        return iam::Error(StatusCode::FORBIDDEN, "Use the local AgentLink address.")
            .into_response();
    }
    // Require a non-form content type even for logout, which has no request body.
    if request.method() == axum::http::Method::POST
        && request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
    {
        return iam::Error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Send application/json.")
            .into_response();
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn router(app: App) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../web/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../web/style.css"),
                )
            }),
        )
        .route(
            "/annseraf-mark-navy.svg",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "image/svg+xml")],
                    include_str!("../web/annseraf-mark-navy.svg"),
                )
            }),
        )
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/api/session", get(current_user).post(sign_in))
        .route("/api/session/logout", post(sign_out))
        .route("/api/account/password", post(change_password))
        .route("/api/people", get(people).post(add_user))
        .route("/api/people/{id}/access", post(change_access))
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(app.clone(), local_only))
        .with_state(app)
}

fn database_path() -> std::io::Result<PathBuf> {
    let path =
        PathBuf::from(env::var_os("AGENTLINK_STATE_DIR").unwrap_or_else(|| ".agentlink".into()));
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::other(
            "State directory must be a private directory (mode 0700).",
        ));
    }
    let db = path.join("agentlink.sqlite3");
    if fs::symlink_metadata(&db).is_ok_and(|m| !m.is_file()) {
        return Err(std::io::Error::other(
            "State database must be a regular file.",
        ));
    }
    Ok(db)
}

fn prompt_bootstrap(db: &mut Connection) -> Result<(), String> {
    if iam::initialized(db).map_err(|error| error.1)? {
        println!("Existing AgentLink accounts retained.");
        return Ok(());
    }
    let mut terminal = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(FsPath::new("/dev/tty"))
        .map_err(|_| "Run first setup from an interactive terminal.")?;
    write!(terminal, "Initial admin email: ").map_err(|e| e.to_string())?;
    let mut email = String::new();
    BufReader::new(&terminal)
        .read_line(&mut email)
        .map_err(|e| e.to_string())?;
    let email = iam::normalize_email(&email).map_err(|error| error.1)?;
    let supplied = rpassword::prompt_password("Temporary admin password (Enter to generate): ")
        .map_err(|e| e.to_string())?;
    let generated = supplied.is_empty();
    let password = if generated {
        iam::random_token().map_err(|error| error.1)?
    } else {
        iam::validate_password(&supplied).map_err(|error| error.1)?;
        if supplied
            != rpassword::prompt_password("Confirm temporary admin password: ")
                .map_err(|e| e.to_string())?
        {
            return Err("Passwords differ. Run setup again.".into());
        }
        supplied
    };
    if iam::bootstrap(db, &email, &password).map_err(|error| error.1)? {
        writeln!(terminal, "Initial admin: {email}").map_err(|e| e.to_string())?;
        if generated {
            writeln!(terminal, "Temporary password: {password}").map_err(|e| e.to_string())?;
        }
        writeln!(terminal, "Change the temporary password at first sign-in.")
            .map_err(|e| e.to_string())?;
    } else {
        println!("Existing AgentLink accounts retained.");
    }
    Ok(())
}

async fn run() -> Result<(), String> {
    let command = env::args()
        .nth(1)
        .filter(|v| matches!(v.as_str(), "bootstrap" | "serve"))
        .filter(|_| env::args_os().len() == 2)
        .ok_or("Usage: agentlink bootstrap|serve")?;
    let path = database_path().map_err(|e| e.to_string())?;
    let mut db = iam::open(&path).map_err(|error| error.1)?;
    if command == "bootstrap" {
        return prompt_bootstrap(&mut db);
    }
    if !iam::initialized(&db).map_err(|error| error.1)? {
        return Err("Run ./setup.sh to create the initial admin first.".into());
    }
    let port: u16 = env::var("AGENTLINK_PORT")
        .unwrap_or_else(|_| "8787".into())
        .parse()
        .map_err(|_| "AGENTLINK_PORT must be a number from 1 to 65535.")?;
    if port == 0 {
        return Err("AGENTLINK_PORT must be a number from 1 to 65535.".into());
    }
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let listener = TcpListener::bind(address)
        .await
        .map_err(|e| format!("Cannot bind {address}: {e}"))?;
    let app = App {
        authority: address.to_string().into(),
        dummy_hash: iam::dummy_hash().map_err(|error| error.1)?.into(),
        db: Arc::new(Mutex::new(db)),
        slots: Arc::new(Semaphore::new(8)),
    };
    println!("AgentLink by Annseraf listening at http://{address}/");
    axum::serve(listener, router(app))
        .await
        .map_err(|e| e.to_string())
}

#[tokio::main(worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("AgentLink: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
