"""End-to-end synthetic Cloud v1 peer with isolated TLS, accounts and state."""

import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from smoke import request


class Peer(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        if self.path == "/unexpected-destination":
            self.server.followed_redirect = True
            self.send_error(400)
            return
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        cloud = self.server
        installation = data["installation"]
        assert data["version"] == 1 and len(bytes.fromhex(installation)) == 32
        assert self.headers.get("Cookie") is None
        if self.path.endswith("/claim"):
            assert set(data) == {"version", "proof", "installation", "credential", "name"}
            assert data["proof"] == cloud.proof and data["name"] == "Fixture engine"
            assert len(bytes.fromhex(data["credential"])) == 32
            if cloud.claim:
                assert cloud.claim == data
            cloud.claim = data
        else:
            assert self.path == "/api/v1/enrollment/refresh"
            assert set(data) == {"version", "installation"}
            assert installation == cloud.claim["installation"]
            assert self.headers["Authorization"] == "Bearer " + cloud.claim["credential"]
        if cloud.mode == "stall":
            time.sleep(10)
            return
        if cloud.mode == "redirect":
            self.send_response(307)
            self.send_header("Location", "/unexpected-destination")
            self.end_headers()
            return
        code = {"offline": 503, "denied": 403, "incompatible": 422}.get(cloud.mode, 200)
        self.send_response(code)
        self.end_headers()
        if code == 200:
            expires = datetime.now(timezone.utc) + timedelta(seconds=295)
            self.wfile.write(json.dumps({"version": 1, "engine_id": cloud.engine,
                "hosted": True, "valid_until": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}).encode())


def tls_fixture(folder):
    # An explicit private CA signs a localhost-only leaf.
    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=folder, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Fixture CA",
            "-addext", "basicConstraints=critical,CA:TRUE")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "peer.key",
            "-out", "peer.csr", "-subj", "/CN=localhost")
    (folder / "extensions").write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", "peer.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-days", "1", "-out", "peer.pem", "-extfile", "extensions")
    cloud = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(folder / "peer.pem", folder / "peer.key")
    cloud.socket = ctx.wrap_socket(cloud.socket, server_side=True)
    cloud.followed_redirect = False
    cloud.mode, cloud.claim = "offline", None
    cloud.proof, cloud.engine = secrets.token_hex(32), secrets.token_hex(32)
    threading.Thread(target=cloud.serve_forever, daemon=True).start()
    return cloud


def exercise(folder, binary):
    state = folder / "state"
    state.mkdir(mode=0o700)
    cloud = tls_fixture(folder)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    origin = f"https://127.0.0.1:{cloud.server_port}"
    env = dict(os.environ, AGENTLINK_PORT=str(port), AGENTLINK_STATE_DIR=str(state),
               AGENTLINK_CLOUD_ORIGIN=origin, AGENTLINK_CLOUD_CA=str(folder / "ca.pem"))
    # First serve creates the IAM schema, then requires an initial admin.
    result = subprocess.run([binary, "serve"], env=env, capture_output=True, timeout=10)
    assert result.returncode == 1 and b"initial admin" in result.stderr
    db = sqlite3.connect(state / "agentlink.sqlite3", timeout=5)
    cookies = {}
    for i, role in enumerate(["admin", "member"], 1):
        token = secrets.token_hex(32)
        db.execute("INSERT INTO users(id,email,password_hash,role,must_change) VALUES(?,?,'fixture',?,0)",
                   (i, role + "@example.invalid", role))
        db.execute("INSERT INTO sessions VALUES(?,?,unixepoch()+3600)",
                   (hashlib.sha256(token.encode()).digest(), i))
        cookies[role] = "agentlink_session=" + token
    db.commit()
    admin = cookies["admin"]

    @contextlib.contextmanager
    def serve(origin_override=origin):
        proc = subprocess.Popen([binary, "serve"], env={**env, "AGENTLINK_CLOUD_ORIGIN": origin_override},
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 20
            while True:
                try:
                    request(port, "/healthz", 200)
                    break
                except OSError:
                    assert proc.poll() is None and time.monotonic() < deadline
                    time.sleep(.05)
            yield
        finally:
            proc.terminate()
            output = b"".join(proc.communicate(timeout=10))
            secret_values = [cloud.proof]
            if cloud.claim:
                secret_values.append(cloud.claim["credential"])
            assert all(value.encode() not in output for value in secret_values)

    def status():
        return json.loads(request(port, "/api/cloud", 200, cookie=admin)[2])

    def expect(state, *, hosted=False):
        deadline = time.monotonic() + 18
        while time.monotonic() < deadline:
            current = status()
            if current["state"] == state:
                assert current["hosted"] == hosted
                return
            time.sleep(.1)
        raise AssertionError((state, current))

    def due():
        db.execute("UPDATE cloud_pair SET due=0")
        db.commit()

    def pair(cookie, code, **changes):
        request(port, "/api/cloud/pair", code, cookie=cookie, data={
            "origin": origin, "consent": True, "proof": cloud.proof, "name": "Fixture engine", **changes})

    with serve():
        pair(None, 401)
        pair(cookies["member"], 403)
        pair(admin, 400, consent=False)
        pair(admin, 400, origin="https://other.invalid")
        expect("unpaired")
        assert cloud.claim is None
        pair(admin, 202)
        expect("offline")
        first = cloud.claim.copy()
    cloud.mode = "ok"
    with serve():
        expect("connected", hosted=True)
        assert first == cloud.claim
        assert db.execute("SELECT proof FROM cloud_pair").fetchone() == (None,)
        cloud.mode = "stall"
        due()
        request(port, "/api/people", 200, cookie=admin)
        expect("offline")
        cloud.mode = "incompatible"
        due()
        expect("incompatible")
        cloud.mode = "redirect"
        due()
        expect("offline")
        assert not cloud.followed_redirect
        cloud.mode = "ok"
        due()
        expect("connected", hosted=True)
        db.execute("UPDATE cloud_pair SET expires=unixepoch()-1")
        db.commit()
        expect("expired")
    with serve("https://127.0.0.1:1"):
        expect("origin changed")
        request(port, "/api/people", 200, cookie=admin)
    cloud.mode = "denied"
    with serve():
        expect("revoked")
        assert db.execute("SELECT credential,proof FROM cloud_pair").fetchone() == (None,None)
        cloud.mode, cloud.claim, cloud.proof = "ok", None, secrets.token_hex(32)
        pair(admin, 202)
        expect("connected", hosted=True)
        assert cloud.claim["installation"] == first["installation"]
        assert cloud.claim["credential"] != first["credential"]
        request(port, "/api/cloud/disconnect", 403, cookie=cookies["member"], data={})
        request(port, "/api/cloud/disconnect", 204, cookie=admin, data={})
        expect("unpaired")
        assert db.execute("SELECT credential,proof FROM cloud_pair").fetchone() == (None,None)
        events = {r[0] for r in db.execute("SELECT event FROM cloud_events")}
        assert {"consent","offline","connected","incompatible","revoked","disconnect"} <= events
    cloud.shutdown()
    cloud.server_close()
    db.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        exercise(Path(directory), sys.argv[1])
    print("Cloud enrollment HTTPS fixture passed")
