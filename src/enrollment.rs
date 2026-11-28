use super::{App, iam, session};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use reqwest::{Client, Url};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env, fs, time::Duration};

pub struct Cloud {
    origin: String,
    client: Client,
}

impl Cloud {
    pub fn configured() -> Option<Self> {
        let value = env::var("AGENTLINK_CLOUD_ORIGIN").ok()?;
        let result = Self::new(&value);
        if result.is_none() {
            eprintln!("Cloud enrollment configuration is invalid. Local operation continues.");
        }
        result
    }

    fn new(value: &str) -> Option<Self> {
        let url = Url::parse(value).ok()?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.host().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(8));
        if let Some(path) = env::var_os("AGENTLINK_CLOUD_CA") {
            let pem = fs::read(path).ok()?;
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&pem).ok()?);
        }
        Some(Self {
            origin: url.origin().ascii_serialization(),
            client: builder.build().ok()?,
        })
    }
}

pub fn initialize(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "PRAGMA secure_delete=ON;
        CREATE TABLE IF NOT EXISTS cloud_pair (
          slot INTEGER PRIMARY KEY CHECK(slot=1), installation TEXT NOT NULL,
          origin TEXT, name TEXT, credential TEXT, proof TEXT, engine TEXT,
          state TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0,
          attempts INTEGER NOT NULL DEFAULT 0, due INTEGER NOT NULL DEFAULT 0,
          hosted INTEGER NOT NULL DEFAULT 0, expires INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS cloud_events (
          id INTEGER PRIMARY KEY, occurred INTEGER NOT NULL DEFAULT(unixepoch()),
          actor INTEGER REFERENCES users(id), event TEXT NOT NULL
        );
        UPDATE cloud_pair SET hosted=0, expires=0, due=0, revision=revision+1,
          state=CASE WHEN state='connected' THEN 'checking' ELSE state END;",
    )
}

#[derive(Serialize)]
pub struct Status {
    origin: Option<String>,
    state: String,
    hosted: bool,
}

pub async fn status(State(app): State<App>, headers: HeaderMap) -> iam::Result<Json<Status>> {
    let token = session(&headers)?;
    let origin = app.cloud.as_ref().map(|cloud| cloud.origin.clone());
    app.query(move |db| {
        let tx = db.transaction()?;
        iam::admin(&tx, &token)?;
        let saved = tx
            .query_row(
                "SELECT origin,state,hosted AND expires>unixepoch(),
          expires<=unixepoch() FROM cloud_pair WHERE slot=1",
                [],
                |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, bool>(2)?,
                        r.get::<_, bool>(3)?,
                    ))
                },
            )
            .optional()?;
        let (state, hosted) = match saved {
            Some((Some(bound), _, _, _)) if origin.as_ref() != Some(&bound) => {
                ("origin changed".to_owned(), false)
            }
            Some((_, state, _, true)) if state == "connected" => ("expired".to_owned(), false),
            Some((_, state, hosted, _)) => (state, hosted),
            None => ("unpaired".to_owned(), false),
        };
        Ok(Json(Status {
            origin,
            state,
            hosted,
        }))
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pair {
    origin: String,
    consent: bool,
    proof: String,
    name: String,
}

fn hex_token(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub async fn pair(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<Pair>,
) -> iam::Result<StatusCode> {
    let token = session(&headers)?;
    let origin = app.cloud.as_ref().map(|c| c.origin.clone());
    app.query(move |db| {
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let actor = iam::admin(&tx, &token)?;
        if !input.consent
            || origin.as_ref() != Some(&input.origin)
            || !hex_token(&input.proof)
            || input.name.trim().is_empty()
            || input.name.trim().len() > 100
        {
            return Err(iam::Error(
                StatusCode::BAD_REQUEST,
                "Confirm the configured Cloud origin and enter a valid name and proof.",
            ));
        }
        let changed = tx.execute(
            "INSERT INTO cloud_pair(slot,installation,origin,name,credential,proof,state)
          VALUES(1,?1,?2,?3,?4,?5,'pending')
          ON CONFLICT(slot) DO UPDATE SET origin=excluded.origin,name=excluded.name,
          credential=excluded.credential,proof=excluded.proof,state='pending',engine=NULL,
          attempts=0,due=0,expires=0,hosted=0,revision=revision+1
          WHERE cloud_pair.credential IS NULL",
            params![
                iam::random_token()?,
                input.origin,
                input.name.trim(),
                iam::random_token()?,
                input.proof
            ],
        )?;
        if changed == 0 {
            return Err(iam::Error(
                StatusCode::CONFLICT,
                "A pairing is active or pending. Disconnect before starting another.",
            ));
        }
        tx.execute(
            "INSERT INTO cloud_events(actor,event) VALUES(?1,'consent')",
            [actor.id],
        )?;
        tx.commit()?;
        Ok(StatusCode::ACCEPTED)
    })
    .await
}

pub async fn disconnect(State(app): State<App>, headers: HeaderMap) -> iam::Result<StatusCode> {
    let token = session(&headers)?;
    app.query(move |db| {
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let actor = iam::admin(&tx, &token)?;
        let changed = tx.execute(
            "UPDATE cloud_pair SET credential=NULL, proof=NULL, engine=NULL, origin=NULL,
                name=NULL, state='unpaired', hosted=0, expires=0, revision=revision+1
             WHERE slot=1 AND state!='unpaired'",
            [],
        )?;
        if changed > 0 {
            tx.execute(
                "INSERT INTO cloud_events(actor,event) VALUES(?1,'disconnect')",
                [actor.id],
            )?;
        }
        tx.commit()?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

struct Work {
    revision: i64,
    installation: String,
    credential: String,
    name: String,
    proof: Option<String>,
    engine: Option<String>,
}

#[derive(Deserialize)]
struct Entitlement {
    version: u32,
    engine_id: String,
    hosted: bool,
    valid_until: String,
}

enum Update {
    Valid(Entitlement),
    Failed(&'static str),
    Denied,
}

impl Cloud {
    async fn exchange(&self, w: &Work, claim: bool) -> Update {
        let (path, body) = if claim {
            (
                "claim",
                json!({"version":1,"installation":w.installation,"credential":w.credential,"name":w.name,"proof":w.proof}),
            )
        } else {
            (
                "refresh",
                json!({"version":1,"installation":w.installation}),
            )
        };
        let mut request = self
            .client
            .post(format!("{}/api/v1/enrollment/{}", self.origin, path))
            .json(&body);
        if !claim {
            request = request.bearer_auth(&w.credential);
        }
        let Ok(mut response) = request.send().await else {
            return Update::Failed("offline");
        };
        match response.status() {
            StatusCode::FORBIDDEN => return Update::Denied,
            StatusCode::UNPROCESSABLE_ENTITY => return Update::Failed("incompatible"),
            StatusCode::OK => (),
            _ => return Update::Failed("offline"),
        }
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if chunk.len() <= 4096 - bytes.len() => {
                    bytes.extend_from_slice(&chunk)
                }
                Ok(None) => break,
                _ => return Update::Failed("invalid response body"),
            }
        }
        match serde_json::from_slice::<Entitlement>(&bytes) {
            Ok(e) if e.version != 1 => Update::Failed("incompatible"),
            Ok(e)
                if hex_token(&e.engine_id)
                    && w.engine.as_ref().is_none_or(|id| id == &e.engine_id) =>
            {
                Update::Valid(e)
            }
            _ => Update::Failed("invalid response"),
        }
    }
}

async fn step(app: &App, cloud: &Cloud) -> iam::Result<()> {
    let origin = cloud.origin.clone();
    let work = app
        .query(move |db| {
            Ok(db
                .query_row(
                    "SELECT revision,installation,credential,name,proof,engine FROM cloud_pair
        WHERE slot=1 AND origin=?1 AND credential IS NOT NULL AND due<=unixepoch()",
                    [origin],
                    |r| {
                        Ok(Work {
                            revision: r.get(0)?,
                            installation: r.get(1)?,
                            credential: r.get(2)?,
                            name: r.get(3)?,
                            proof: r.get(4)?,
                            engine: r.get(5)?,
                        })
                    },
                )
                .optional()?)
        })
        .await?;
    let Some(w) = work else { return Ok(()) };
    let mut update = cloud.exchange(&w, w.proof.is_some()).await;
    if matches!(update, Update::Denied) && w.proof.is_some() {
        // The original claim may have committed before its response was lost.
        update = cloud.exchange(&w, false).await;
    }
    app.query(move |db| save_result(db, w, update)).await
}

fn save_result(db: &mut Connection, work: Work, update: Update) -> iam::Result<()> {
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let previous: Option<String> = tx
        .query_row(
            "SELECT state FROM cloud_pair WHERE slot=1 AND revision=?1",
            [work.revision],
            |row| row.get(0),
        )
        .optional()?;
    // Disconnect or a newer claim invalidates every in-flight result.
    let Some(previous) = previous else {
        return Ok(());
    };
    let state = match update {
        Update::Valid(entitlement) => {
            let until: Option<i64> = tx
                .query_row(
                    "SELECT unixepoch(?1) WHERE ?1 GLOB '????-??-??T??:??:??*Z'
                 AND unixepoch(?1)>unixepoch() AND unixepoch(?1)<=unixepoch()+300",
                    [entitlement.valid_until],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(until) = until {
                tx.execute(
                    "UPDATE cloud_pair SET engine=?1, proof=NULL, hosted=?2, expires=?3, attempts=0,
                     due=MAX(unixepoch()+1,?3-60) WHERE slot=1",
                    params![entitlement.engine_id, entitlement.hosted, until]
                )?;
                "connected"
            } else {
                "invalid entitlement expiry"
            }
        }
        Update::Failed(reason) => reason,
        Update::Denied => {
            tx.execute(
                "UPDATE cloud_pair SET credential=NULL, proof=NULL WHERE slot=1",
                [],
            )?;
            if work.proof.is_some() {
                "pairing denied"
            } else {
                "revoked"
            }
        }
    };
    if state != "connected" {
        tx.execute(
            "UPDATE cloud_pair SET hosted=0, expires=0, attempts=MIN(6,attempts+1),
             due=unixepoch()+MIN(120,2 << attempts) WHERE slot=1",
            [],
        )?;
    }
    tx.execute(
        "UPDATE cloud_pair SET state=?1, revision=revision+1 WHERE slot=1",
        [state],
    )?;
    if previous != state {
        tx.execute("INSERT INTO cloud_events(event) VALUES(?1)", [state])?;
    }
    tx.commit()?;
    Ok(())
}

pub async fn worker(app: App) {
    let Some(cloud) = app.cloud.clone() else {
        return;
    };
    loop {
        if step(&app, &cloud).await.is_err() {
            eprintln!("Cloud enrollment state temporarily unavailable.");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
