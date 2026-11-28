//! Local pull transport for registered ordinary-text senders and adapter workers.
use super::{App, iam};
use agentlink::{
    adapter::{Binding, ContractError, TextEnvelope},
    delivery::{Attempt, Outcome, Queue, QueueError, Reconciliation},
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    binding: Binding,
    sender_sha256: String,
    worker_sha256: String,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Command {
    Enqueue {
        envelope: TextEnvelope,
    },
    Claim,
    Finish {
        attempt: Attempt,
        outcome: Outcome,
    },
    Unconfirmed {
        after_id: i64,
    },
    Reconcile {
        attempt: Attempt,
        result: Reconciliation,
    },
}

const DENIED: iam::Error = iam::Error(StatusCode::FORBIDDEN, "Adapter access denied.");

fn queue_error(error: QueueError) -> iam::Error {
    match error {
        QueueError::InvalidEnvelope(ContractError::BindingMismatch) => DENIED,
        QueueError::InvalidEnvelope(_) => {
            iam::Error(StatusCode::BAD_REQUEST, "Invalid text envelope.")
        }
        QueueError::DuplicateConflict => {
            iam::Error(StatusCode::CONFLICT, "Delivery key already used.")
        }
        QueueError::InvalidTime | QueueError::Storage(_) => iam::INTERNAL,
    }
}

pub(super) async fn handle(
    State(app): State<App>,
    headers: HeaderMap,
    Json(cmd): Json<Command>,
) -> iam::Result<Json<Value>> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(DENIED)?;
    let digest = hex::encode(Sha256::digest(token.as_bytes()));
    let path = app.db_path.clone();
    let permit = app
        .slots
        .try_acquire_owned()
        .map_err(|_| iam::Error(StatusCode::SERVICE_UNAVAILABLE, "Engine busy."))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let registrations =
            std::fs::read(path.with_file_name("text-adapters.json")).map_err(|_| DENIED)?;
        let registrations: Vec<Registration> =
            serde_json::from_slice(&registrations).map_err(|_| DENIED)?;
        // A credential must identify exactly one binding and exactly one role.
        let mut matches = registrations
            .iter()
            .flat_map(|r| {
                [
                    (&r.sender_sha256, &r.binding, true),
                    (&r.worker_sha256, &r.binding, false),
                ]
            })
            .filter(|(hash, _, _)| **hash == digest);
        let (_, binding, sender) = matches.next().ok_or(DENIED)?;
        if matches.next().is_some() || sender != matches!(cmd, Command::Enqueue { .. }) {
            return Err(DENIED);
        }
        let mut queue = Queue::scoped(path.as_ref(), binding.clone()).map_err(queue_error)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| iam::INTERNAL)?
            .as_secs();
        let response = match cmd {
            Command::Enqueue { envelope } => {
                json!({"id":queue.enqueue(&envelope, now).map_err(queue_error)?})
            }
            Command::Claim => json!(queue.claim(now).map_err(queue_error)?),
            Command::Unconfirmed { after_id } => {
                json!(queue.unconfirmed(after_id).map_err(queue_error)?)
            }
            Command::Finish { attempt, outcome } => {
                json!({"applied":queue.finish(attempt,outcome,now).map_err(queue_error)?})
            }
            Command::Reconcile { attempt, result } => {
                json!({"applied":queue.reconcile(attempt,result,now).map_err(queue_error)?})
            }
        };
        Ok(Json(response))
    })
    .await
    .map_err(|_| iam::INTERNAL)?
}
