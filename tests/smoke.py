"""Exercise the native installer and HTTP IAM against isolated disposable state."""
import concurrent.futures
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import signal
import socket
import sqlite3
import subprocess
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
ADMIN = "admin@example.invalid"
OTHER_ADMIN = "second@example.invalid"
MEMBER = "member@example.invalid"
BUILD_TIMEOUT = 1800


class Setup:
    def __init__(self, state, port, *args):
        self.pid, self.master = pty.fork()
        if self.pid == 0:
            os.chdir(ROOT)
            os.environ.update(AGENTLINK_STATE_DIR=str(state), AGENTLINK_PORT=str(port))
            os.execv("./setup.sh", ["./setup.sh", *args])
        self.output = b""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.master)
        if self.pid is None:
            return
        try:
            os.kill(self.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        os.waitpid(self.pid, 0)

    def expect_exit(self, expected):
        _, status = os.waitpid(self.pid, 0)
        self.pid = None
        assert os.waitstatus_to_exitcode(status) == expected

    def expect(self, pattern, *, timeout=30):
        deadline = time.monotonic() + timeout
        while not (match := re.search(pattern, self.output)):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.master], [], [], remaining)[0]:
                raise AssertionError(f"Timeout waiting for {pattern!r}")
            try:
                chunk = os.read(self.master, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b""
            if not chunk:
                raise AssertionError(f"Setup exited before {pattern!r}")
            self.output += chunk
        self.output = self.output[match.end():]
        return match

    def type(self, value, *, secret=False):
        if secret:
            deadline = time.monotonic() + 5
            while termios.tcgetattr(self.master)[3] & termios.ECHO:
                if time.monotonic() > deadline:
                    raise AssertionError("Password prompt did not disable terminal echo")
                time.sleep(0.01)
        os.write(self.master, value.encode() + b"\n")


def request(port, path, status, *, data=None, cookie=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    options = {} if headers is None else headers.copy()
    if cookie:
        options["Cookie"] = cookie
    if data is not None:
        options.setdefault("Content-Type", "application/json")
    try:
        conn.request("GET" if data is None else "POST", path, json.dumps(data) if data is not None else None, options)
        response = conn.getresponse()
        body = response.read()
        assert response.status in (status if isinstance(status, tuple) else (status,)), (path, status, response.status)
        return response.status, response.getheader("Set-Cookie"), body
    finally:
        conn.close()


def login(port, email, password, status=204):
    _, cookie, _ = request(port, "/api/session", status, data={"email": email, "password": password})
    if cookie:
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
        return cookie.split(";", 1)[0]
    return None


def change_password(port, cookie, old, new):
    request(port, "/api/account/password", 204, cookie=cookie,
            data={"current_password": old, "new_password": new})
    request(port, "/api/session", 401, cookie=cookie)


def add(port, admin, email, password, role, status=201):
    _, _, body = request(port, "/api/people", status, cookie=admin,
                         data={"email": email, "password": password, "role": role})
    return json.loads(body)


def access(port, admin, person, action, status, **fields):
    return request(port, f"/api/people/{person['id']}/access", status,
                   cookie=admin, data={"action": action, **fields})[0]


def recover_admin(port, state, old_cookie, old_password, member_cookie, admin_id):
    local_env = dict(os.environ, AGENTLINK_STATE_DIR=str(state))
    detached = subprocess.run(
        ["./setup.sh", "reset-admin", ADMIN], cwd=ROOT, env=local_env,
        start_new_session=True, stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
    )
    assert detached.returncode == 1
    assert b"requires an interactive terminal" in detached.stderr
    request(port, "/api/session", 200, cookie=old_cookie)

    with Setup(state, port, "reset-admin", MEMBER) as denied:
        denied.expect(rb"No active administrator has that email.")
        denied.expect_exit(1)
    request(port, "/api/session", 200, cookie=member_cookie)

    temporary, permanent = (secrets.token_hex(20) for _ in range(2))
    with Setup(state, port, "reset-admin", ADMIN.upper()) as recovery:
        recovery.expect(rb"New temporary admin password: ")
        recovery.type(temporary, secret=True)
        prompt = recovery.expect(rb"Confirm temporary admin password: ").string
        assert temporary.encode() not in prompt
        recovery.type(temporary, secret=True)
        output = recovery.expect(rb"Admin password reset\. Previous sessions revoked\.").string
        assert temporary.encode() not in output
        recovery.expect_exit(0)

    request(port, "/api/session", 401, cookie=old_cookie)
    request(port, "/api/session", 200, cookie=member_cookie)
    login(port, ADMIN, old_password, 401)
    recovered = login(port, ADMIN, temporary)
    _, _, body = request(port, "/api/session", 200, cookie=recovered)
    assert json.loads(body)["id"] == admin_id
    request(port, "/api/people", 403, cookie=recovered)
    change_password(port, recovered, temporary, permanent)
    return login(port, ADMIN, permanent)


def exercise(port, state):
    admin_password = secrets.token_hex(20)
    member_initial, member_password, reset_password = (secrets.token_hex(20) for _ in range(3))
    other_initial, other_password = (secrets.token_hex(20) for _ in range(2))
    with Setup(state, port) as setup:
        setup.expect(rb"Initial admin email: ", timeout=BUILD_TIMEOUT)
        setup.type(ADMIN)
        setup.expect(rb"Temporary admin password \(Enter to generate\): ")
        setup.type("", secret=True)
        initial = setup.expect(rb"Temporary password: ([a-f0-9]{64})").group(1).decode()
        setup.expect(rb"listening at http://127\.0\.0\.1:")
        assert request(port, "/healthz", 200)[2] == b"ok\n"
        assert b"AgentLink" in request(port, "/", 200)[2]
        request(port, "/annseraf-mark-navy.svg", 200)
        request(port, "/healthz", 403, headers={"Host": "example.invalid"})
        request(port, "/api/session", 403, data={}, headers={"Origin": "https://example.invalid"})
        request(port, "/api/session/logout", 415, data={}, headers={"Content-Type": "text/plain"})
        admin = login(port, ADMIN, initial)
        request(port, "/api/people", 403, cookie=admin)
        change_password(port, admin, initial, admin_password)
        login(port, ADMIN, initial, 401)
        admin = login(port, ADMIN.upper(), admin_password)
        _, _, body = request(port, "/api/session", 200, cookie=admin)
        primary = json.loads(body)
        assert not primary["must_change"]
        access(port, admin, primary, "disable", 409)
        member = add(port, admin, MEMBER, member_initial, "member")
        add(port, admin, MEMBER.upper(), member_initial, "member", 409)
        member_cookie = login(port, MEMBER, member_initial)
        change_password(port, member_cookie, member_initial, member_password)
        signed_out = login(port, MEMBER, member_password)
        request(port, "/api/session/logout", 204, cookie=signed_out, data={})
        request(port, "/api/session", 401, cookie=signed_out)
        member_cookie = login(port, MEMBER, member_password)
        request(port, "/api/people", 403, cookie=member_cookie)
        add(port, member_cookie, "blocked@example.invalid", member_initial, "admin", 403)
        access(port, member_cookie, primary, "disable", 403)
        access(port, member_cookie, primary, "enable", 403, password=member_initial)
        access(port, admin, member, "revoke_sessions", 204)
        request(port, "/api/session", 401, cookie=member_cookie)
        member_cookie = login(port, MEMBER, member_password)
        access(port, admin, member, "reset_password", 204, password=reset_password)
        request(port, "/api/session", 401, cookie=member_cookie)
        login(port, MEMBER, member_password, 401)
        member_cookie = login(port, MEMBER, reset_password)
        access(port, admin, member, "disable", 204)
        request(port, "/api/session", 401, cookie=member_cookie)
        login(port, MEMBER, reset_password, 401)
        access(port, member_cookie, member, "enable", 401, password=member_initial)
        access(port, admin, member, "enable", 400, password=reset_password)
        restored_password = secrets.token_hex(20)
        access(port, admin, member, "enable", 204, password=restored_password)
        access(port, admin, member, "enable", 409, password=member_initial)
        request(port, "/api/session", 401, cookie=member_cookie)
        login(port, MEMBER, reset_password, 401)
        restored = login(port, MEMBER, restored_password)
        _, _, body = request(port, "/api/session", 200, cookie=restored)
        restored_profile = json.loads(body)
        assert restored_profile["id"] == member["id"]
        assert restored_profile["role"] == "member" and restored_profile["must_change"]
        change_password(port, restored, restored_password, member_password)
        restored = login(port, MEMBER, member_password)
        admin = recover_admin(port, state, admin, admin_password, restored, primary["id"])
        access(port, admin, primary, "disable", 409)
        other = add(port, admin, OTHER_ADMIN, other_initial, "admin")
        other_cookie = login(port, OTHER_ADMIN, other_initial)
        change_password(port, other_cookie, other_initial, other_password)
        other_cookie = login(port, OTHER_ADMIN, other_password)

    with Setup(state, port) as setup:
        setup.expect(rb"Existing AgentLink accounts retained\.", timeout=BUILD_TIMEOUT)
        setup.expect(rb"listening at http://127\.0\.0\.1:")
        request(port, "/api/session", 200, cookie=admin)
        _, _, body = request(port, "/api/people", 200, cookie=admin)
        assert len(json.loads(body)) == 3
        request(port, "/api/session", 200, cookie=restored)
        login(port, MEMBER, reset_password, 401)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            first = pool.submit(access, port, admin, other, "disable", (204, 401))
            second = pool.submit(access, port, other_cookie, primary, "disable", (204, 401))
            assert sorted([first.result(), second.result()]) == [204, 401]

        assert state.stat().st_mode & 0o777 == 0o700
        with sqlite3.connect(state / "agentlink.sqlite3") as db:
            assert db.execute("SELECT count(*) FROM users WHERE role='admin' AND active=1").fetchone() == (1,)
            assert db.execute("SELECT count(*) FROM users WHERE password_hash LIKE '$argon2id$%'").fetchone() == (3,)
            for (stored,) in db.execute("SELECT digest FROM sessions"):
                assert isinstance(stored, bytes) and len(stored) == 32
            admin_digest = hashlib.sha256(admin.split("=", 1)[1].encode()).digest()
            assert db.execute(
                "SELECT EXISTS(SELECT 1 FROM sessions WHERE digest = ?)", (admin_digest,)
            ).fetchone() == (int(first.result() == 204),)
            assert db.execute("SELECT count(*) FROM account_events WHERE action='disable'").fetchone() == (2,)
            for action, subject in [("enable", member), ("local_admin_recovery", primary)]:
                assert db.execute(
                    "SELECT actor_id, subject_id FROM account_events WHERE action=?", (action,),
                ).fetchall() == [(primary["id"], subject["id"])]
    return initial


def main():
    with tempfile.TemporaryDirectory(prefix="agentlink-smoke-") as scratch:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        initial = exercise(port, Path(scratch) / "first")
        with Setup(Path(scratch) / "second", port) as setup:
            setup.expect(rb"Initial admin email: ", timeout=BUILD_TIMEOUT)
            setup.type(ADMIN)
            setup.expect(rb"Temporary admin password \(Enter to generate\): ")
            setup.type("", secret=True)
            second = setup.expect(rb"Temporary password: ([a-f0-9]{64})").group(1).decode()
            assert initial != second
            setup.expect(rb"listening at http://127\.0\.0\.1:")
            login(port, ADMIN, second)
        with Setup(Path(scratch) / "supplied", port) as setup:
            supplied = secrets.token_hex(20)
            setup.expect(rb"Initial admin email: ", timeout=BUILD_TIMEOUT)
            setup.type(ADMIN)
            setup.expect(rb"Temporary admin password \(Enter to generate\): ")
            setup.type(supplied, secret=True)
            first_prompt = setup.expect(rb"Confirm temporary admin password: ").string
            assert supplied.encode() not in first_prompt
            setup.type(supplied, secret=True)
            output = setup.expect(rb"listening at http://127\.0\.0\.1:").string
            assert supplied.encode() not in output
            login(port, ADMIN, supplied)
    print("PASS: fresh and repeat native setup, IAM enforcement, access restoration, terminal admin recovery and concurrent admin protection")


if __name__ == "__main__":
    main()
