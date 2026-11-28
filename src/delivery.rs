//! Durable queue for validated ordinary text, owned by a trusted engine worker.
//! Enqueue only after resolving and authorizing the destination.

use std::{path::Path, time::Duration};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::adapter::{Binding, ContractError, TextEnvelope, VERSION};

pub const MAX_ATTEMPTS: u32 = 3;
pub const LEASE_SECONDS: u64 = 60;
const INITIAL_BACKOFF_SECONDS: u64 = 5;

#[derive(Debug)]
pub enum QueueError {
    Storage(rusqlite::Error),
    InvalidEnvelope(ContractError),
    DuplicateConflict,
    InvalidTime,
}

impl From<rusqlite::Error> for QueueError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attempt {
    id: i64,
    number: u32,
}

#[derive(Debug)]
pub struct Delivery {
    pub attempt: Attempt,
    pub envelope: TextEnvelope,
}

#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    Delivered,
    /// The adapter definitively did not deliver, and retry may succeed.
    Retryable,
    Rejected,
    Unconfirmed,
}

#[derive(Debug, Clone, Copy)]
pub enum Reconciliation {
    Delivered,
    /// Authoritative confirmation that this attempt did not deliver and cannot
    /// still deliver. An inconclusive lookup must leave the row unconfirmed.
    NotDelivered,
}

pub struct Queue(Connection);

impl Queue {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, QueueError> {
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS ordinary_deliveries (
                id INTEGER PRIMARY KEY,
                tenant TEXT NOT NULL,
                adapter TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                room TEXT NOT NULL,
                thread TEXT,
                body TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'queued'
                    CHECK(state IN ('queued', 'in_flight', 'unconfirmed', 'delivered', 'dead')),
                attempts INTEGER NOT NULL DEFAULT 0,
                due_at INTEGER NOT NULL,
                lease_until INTEGER,
                UNIQUE(tenant, adapter, correlation_id)
            );
            CREATE INDEX IF NOT EXISTS ordinary_deliveries_due
                ON ordinary_deliveries(state, due_at, id);
            CREATE INDEX IF NOT EXISTS ordinary_deliveries_lease
                ON ordinary_deliveries(state, lease_until);",
        )?;
        Ok(Self(db))
    }

    /// Returns the same ID for identical submissions, even after completion.
    /// The key belongs to the tenant and adapter and cannot be reused to change
    /// a destination or payload.
    pub fn enqueue(&mut self, envelope: &TextEnvelope, now: u64) -> Result<i64, QueueError> {
        envelope.validate().map_err(QueueError::InvalidEnvelope)?;
        let now = timestamp(now)?;
        let binding = &envelope.binding;
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO ordinary_deliveries
                (tenant, adapter, correlation_id, room, thread, body, due_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(tenant, adapter, correlation_id) DO NOTHING",
            params![
                binding.tenant,
                binding.adapter,
                envelope.correlation_id,
                binding.room,
                binding.thread,
                envelope.text,
                now
            ],
        )?;
        let id = tx
            .query_row(
                "SELECT id FROM ordinary_deliveries
             WHERE tenant = ?1 AND adapter = ?2 AND correlation_id = ?3
               AND room = ?4 AND thread IS ?5 AND body = ?6",
                params![
                    binding.tenant,
                    binding.adapter,
                    envelope.correlation_id,
                    binding.room,
                    binding.thread,
                    envelope.text
                ],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(QueueError::DuplicateConflict)?;
        tx.commit()?;
        Ok(id)
    }

    /// Atomically leases the earliest eligible row. Expired attempts move to
    /// reconciliation because a worker may have sent before it disappeared.
    pub fn claim(&mut self, now: u64) -> Result<Option<Delivery>, QueueError> {
        let now = timestamp(now)?;
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE ordinary_deliveries SET state = 'unconfirmed', lease_until = NULL
             WHERE state = 'in_flight' AND lease_until <= ?1",
            [now],
        )?;
        let delivery = tx
            .query_row(
                "UPDATE ordinary_deliveries
             SET state = 'in_flight', attempts = attempts + 1, lease_until = ?2
             WHERE id = (
                SELECT id FROM ordinary_deliveries WHERE state = 'queued' AND due_at <= ?1
                ORDER BY due_at, id LIMIT 1
             )
             RETURNING id, attempts, tenant, adapter, correlation_id, room, thread, body",
                params![now, now + LEASE_SECONDS as i64],
                read_delivery,
            )
            .optional()?;
        tx.commit()?;
        Ok(delivery)
    }

    /// Lists at most one page of attempts needing an authoritative status check.
    pub fn unconfirmed(&self, after_id: i64) -> Result<Vec<Delivery>, QueueError> {
        self.list("unconfirmed", after_id)
    }

    /// Lists terminal failures for operator inspection. Dead rows retain their
    /// deduplication keys and cannot be claimed.
    pub fn dead_letters(&self, after_id: i64) -> Result<Vec<Delivery>, QueueError> {
        self.list("dead", after_id)
    }

    fn list(&self, state: &str, after_id: i64) -> Result<Vec<Delivery>, QueueError> {
        let mut statement = self.0.prepare(
            "SELECT id, attempts, tenant, adapter, correlation_id, room, thread, body
             FROM ordinary_deliveries WHERE state = ?1 AND id > ?2
             ORDER BY id LIMIT 100",
        )?;
        let deliveries = statement.query_map(params![state, after_id], read_delivery)?;
        Ok(deliveries.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Returns false when the lease is stale or the attempt was already resolved.
    pub fn finish(&self, attempt: Attempt, outcome: Outcome, now: u64) -> Result<bool, QueueError> {
        self.resolve(attempt, "in_flight", outcome, now)
    }

    pub fn reconcile(
        &self,
        attempt: Attempt,
        result: Reconciliation,
        now: u64,
    ) -> Result<bool, QueueError> {
        let outcome = match result {
            Reconciliation::Delivered => Outcome::Delivered,
            Reconciliation::NotDelivered => Outcome::Retryable,
        };
        self.resolve(attempt, "unconfirmed", outcome, now)
    }

    fn resolve(
        &self,
        attempt: Attempt,
        expected: &str,
        outcome: Outcome,
        now: u64,
    ) -> Result<bool, QueueError> {
        let now = timestamp(now)?;
        let (state, due_at) = match outcome {
            Outcome::Delivered => ("delivered", now),
            Outcome::Rejected => ("dead", now),
            Outcome::Unconfirmed => ("unconfirmed", now),
            Outcome::Retryable if attempt.number >= MAX_ATTEMPTS => ("dead", now),
            Outcome::Retryable => {
                let delay = INITIAL_BACKOFF_SECONDS << (attempt.number - 1);
                ("queued", now + delay as i64)
            }
        };
        Ok(self.0.execute(
            "UPDATE ordinary_deliveries SET state = ?1, due_at = ?2, lease_until = NULL
             WHERE id = ?3 AND attempts = ?4 AND state = ?5
               AND (lease_until IS NULL OR lease_until > ?6)",
            params![state, due_at, attempt.id, attempt.number, expected, now],
        )? == 1)
    }
}

impl Attempt {
    pub fn delivery_id(self) -> i64 {
        self.id
    }

    pub fn number(self) -> u32 {
        self.number
    }
}

fn timestamp(now: u64) -> Result<i64, QueueError> {
    if now > i64::MAX as u64 - LEASE_SECONDS {
        return Err(QueueError::InvalidTime);
    }
    Ok(now as i64)
}

fn read_delivery(row: &rusqlite::Row<'_>) -> rusqlite::Result<Delivery> {
    Ok(Delivery {
        attempt: Attempt {
            id: row.get(0)?,
            number: row.get(1)?,
        },
        envelope: TextEnvelope {
            version: VERSION,
            binding: Binding {
                tenant: row.get(2)?,
                adapter: row.get(3)?,
                room: row.get(5)?,
                thread: row.get(6)?,
            },
            correlation_id: row.get(4)?,
            text: row.get(7)?,
        },
    })
}
