use std::path::PathBuf;

use agentlink::{
    adapter::{Binding, TextEnvelope, VERSION},
    delivery::{LEASE_SECONDS, MAX_ATTEMPTS, Outcome, Queue, QueueError, Reconciliation},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("agentlink-queue-{}", hex::encode(nonce)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn open(&self) -> Queue {
        Queue::open(self.0.join("queue.sqlite")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn message() -> TextEnvelope {
    TextEnvelope {
        version: VERSION,
        binding: Binding {
            tenant: "dev".into(),
            adapter: "fixture".into(),
            room: "lobby".into(),
            thread: Some("thread-1".into()),
        },
        correlation_id: "greeting-1".into(),
        text: "Hello from the fixture".into(),
    }
}

#[test]
fn queued_and_completed_messages_survive_restart_and_dedupe() {
    let fixture = Fixture::new();
    let mut original = message();
    let id = fixture.open().enqueue(&original, 10).unwrap();
    let mut queue = fixture.open();
    let claim = queue.claim(10).unwrap().unwrap();
    assert_eq!(claim.attempt.delivery_id(), id);
    assert_eq!(claim.envelope.binding, original.binding);
    assert_eq!(claim.envelope.text, original.text);
    assert!(fixture.open().claim(10).unwrap().is_none());
    assert!(queue.finish(claim.attempt, Outcome::Delivered, 11).unwrap());

    let mut queue = fixture.open();
    assert_eq!(queue.enqueue(&original, 12).unwrap(), id);
    original.binding.room = "other-room".into();
    assert!(matches!(
        queue.enqueue(&original, 12),
        Err(QueueError::DuplicateConflict)
    ));
    original.binding.room = "lobby".into();
    original.text = "Different payload".into();
    assert!(matches!(
        queue.enqueue(&original, 12),
        Err(QueueError::DuplicateConflict)
    ));
    assert!(queue.claim(12).unwrap().is_none());
    original.binding.tenant = "other-tenant".into();
    assert_ne!(queue.enqueue(&original, 12).unwrap(), id);
}

#[test]
fn retries_survive_restart_and_stop_at_the_attempt_limit() {
    let fixture = Fixture::new();
    let original = message();
    let mut queue = fixture.open();
    let id = queue.enqueue(&original, 10).unwrap();
    let first = queue.claim(10).unwrap().unwrap().attempt;
    assert!(queue.finish(first, Outcome::Retryable, 11).unwrap());
    drop(queue);

    let mut queue = fixture.open();
    assert!(queue.claim(15).unwrap().is_none());
    let second = queue.claim(16).unwrap().unwrap().attempt;
    assert_eq!(second.number(), 2);
    assert!(!queue.finish(first, Outcome::Delivered, 16).unwrap());
    assert!(queue.finish(second, Outcome::Retryable, 17).unwrap());
    assert!(queue.claim(26).unwrap().is_none());
    let third = queue.claim(27).unwrap().unwrap().attempt;
    assert_eq!(third.number(), MAX_ATTEMPTS);
    assert!(queue.finish(third, Outcome::Retryable, 28).unwrap());

    let mut queue = fixture.open();
    assert_eq!(queue.dead_letters(0).unwrap()[0].attempt, third);
    assert_eq!(queue.enqueue(&original, 29).unwrap(), id);
    assert!(queue.claim(1_000).unwrap().is_none());
}

#[test]
fn expired_and_ambiguous_attempts_require_authoritative_reconciliation() {
    let fixture = Fixture::new();
    let mut queue = fixture.open();
    let id = queue.enqueue(&message(), 10).unwrap();
    let first = queue.claim(10).unwrap().unwrap().attempt;
    drop(queue);

    let mut queue = fixture.open();
    let expired = 10 + LEASE_SECONDS;
    assert!(!queue.finish(first, Outcome::Delivered, expired).unwrap());
    assert!(queue.claim(expired).unwrap().is_none());
    assert_eq!(queue.unconfirmed(0).unwrap()[0].attempt, first);
    assert!(queue.claim(1_000).unwrap().is_none());
    assert!(
        queue
            .reconcile(first, Reconciliation::NotDelivered, 1_000)
            .unwrap()
    );
    assert!(queue.claim(1_004).unwrap().is_none());
    let second = queue.claim(1_005).unwrap().unwrap().attempt;
    assert_eq!(second.delivery_id(), id);
    assert!(queue.finish(second, Outcome::Unconfirmed, 1_006).unwrap());
    assert!(
        !queue
            .reconcile(first, Reconciliation::Delivered, 1_007)
            .unwrap()
    );
    assert!(
        queue
            .reconcile(second, Reconciliation::Delivered, 1_007)
            .unwrap()
    );
    assert!(queue.unconfirmed(0).unwrap().is_empty());
    assert!(queue.claim(2_000).unwrap().is_none());
}

#[test]
fn abrupt_worker_exit_keeps_the_lease_and_requires_reconciliation() {
    const CRASH_FIXTURE: &str = "AGENTLINK_TEST_CRASH_DATABASE";
    const EXIT_AFTER_CLAIM: i32 = 42;

    if let Some(path) = std::env::var_os(CRASH_FIXTURE) {
        let mut queue = Queue::open(path).unwrap();
        assert!(queue.claim(10).unwrap().is_some());
        std::process::exit(EXIT_AFTER_CLAIM);
    }

    let fixture = Fixture::new();
    let id = fixture.open().enqueue(&message(), 10).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "abrupt_worker_exit_keeps_the_lease_and_requires_reconciliation",
        ])
        .env(CRASH_FIXTURE, fixture.0.join("queue.sqlite"))
        .output()
        .unwrap()
        .status;
    assert_eq!(status.code(), Some(EXIT_AFTER_CLAIM));

    let mut queue = fixture.open();
    assert!(queue.claim(10 + LEASE_SECONDS - 1).unwrap().is_none());
    assert!(queue.unconfirmed(0).unwrap().is_empty());
    assert!(queue.claim(10 + LEASE_SECONDS).unwrap().is_none());
    assert_eq!(queue.unconfirmed(0).unwrap()[0].attempt.delivery_id(), id);
}

#[test]
fn concurrent_workers_cannot_claim_the_same_message() {
    let fixture = Fixture::new();
    fixture.open().enqueue(&message(), 10).unwrap();
    let mut first = fixture.open();
    let mut second = fixture.open();
    let barrier = std::sync::Barrier::new(2);
    let claims = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            barrier.wait();
            first.claim(10).unwrap()
        });
        barrier.wait();
        let other = second.claim(10).unwrap();
        [worker.join().unwrap(), other]
    });
    assert_eq!(claims.into_iter().flatten().count(), 1);
}
