"""Synthetic loopback adapter lifecycle, using the built debug engine."""
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
import secrets
import select
import socket
import sqlite3
import subprocess
import tempfile

from smoke import ROOT, request

ENGINE = ROOT / "target/debug/agentlink"


@contextmanager
def serve(env):
    proc = subprocess.Popen([ENGINE, "serve"], env=env, stdout=subprocess.PIPE)
    try:
        assert select.select([proc.stdout], [], [], 15)[0]
        assert b"listening" in proc.stdout.readline()
        yield
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def main(state):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = dict(os.environ, AGENTLINK_STATE_DIR=str(state), AGENTLINK_PORT=str(port))
    db = state / "agentlink.sqlite3"
    setup = subprocess.run([ENGINE, "serve"], env=env, capture_output=True, timeout=15)
    assert setup.returncode == 1 and b"initial admin" in setup.stderr
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO users(email,password_hash,role,must_change) VALUES ('fixture@invalid','unused','admin',1)")

    def call(token, action, status=200, **fields):
        _, _, body = request(port, "/api/adapter/text", status, data=dict(action=action, **fields),
                             headers={"Authorization": "Bearer " + token})
        return json.loads(body)

    def registration(thread):
        binding = dict(tenant="local", adapter="fixture", room="room", thread=thread)
        sender, worker = secrets.token_hex(32), secrets.token_hex(32)
        def digest(value):
            return hashlib.sha256(value.encode("ascii")).hexdigest()
        return sender, worker, dict(binding=binding, sender_sha256=digest(sender), worker_sha256=digest(worker))

    sender, worker, first = registration(None)
    _, foreign, second = registration("private")
    config = state / "text-adapters.json"
    config.write_text(json.dumps([first, second]))
    message = dict(version=1, binding=first["binding"], correlation_id="abc", text="x" * 16384)
    with serve(env):
        call(secrets.token_hex(32), "claim", 403)
        call(sender, "claim", 403)
        call(worker, "enqueue", 403, envelope=message)
        call(sender, "enqueue", 403, envelope=dict(message, binding=second["binding"]))
        delivery = call(sender, "enqueue", envelope=message)
        assert call(sender, "enqueue", envelope=message) == delivery
        call(sender, "enqueue", 409, envelope=dict(message, text="changed"))
        assert call(foreign, "claim") is None

    with serve(env):
        claimed = call(worker, "claim")
        assert claimed["envelope"] == message
        attempt = claimed["attempt"]
        assert attempt == dict(id=delivery["id"], number=1)
        assert not call(foreign, "finish", attempt=attempt, outcome="delivered")["applied"]
        assert call(sender, "enqueue", envelope=message) == delivery
        assert call(worker, "claim") is None

    # Model a worker disappearing after provider acceptance, before acknowledging.
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE ordinary_deliveries SET lease_until=0 WHERE id=?", (delivery["id"],))
    with serve(env):
        assert call(worker, "claim") is None
        assert call(foreign, "unconfirmed", after_id=0) == []
        assert call(worker, "unconfirmed", after_id=0) == [claimed]
        assert not call(foreign, "reconcile", attempt=attempt, result="delivered")["applied"]
        assert call(worker, "reconcile", attempt=attempt, result="delivered")["applied"]
        assert call(sender, "enqueue", envelope=message) == delivery
        assert call(worker, "claim") is None
        assert call(worker, "unconfirmed", after_id=0) == []
        next_message = dict(message, correlation_id="def", text="second delivery")
        second_id = call(sender, "enqueue", envelope=next_message)["id"]
        next_attempt = call(worker, "claim")["attempt"]
        assert next_attempt["id"] == second_id
        assert not call(worker, "finish", attempt=dict(next_attempt, number=0), outcome="retryable")["applied"]
        assert call(worker, "finish", attempt=next_attempt, outcome="delivered")["applied"]
        assert not call(worker, "finish", attempt=next_attempt, outcome="delivered")["applied"]
        config.write_text(json.dumps([second]))
        call(worker, "claim", 403)
        call(sender, "enqueue", 403, envelope=message)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        main(Path(directory))
    print("Authenticated worker restart, duplicate, reconciliation and isolation checks passed.")
