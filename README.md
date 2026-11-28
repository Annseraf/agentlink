# AgentLink by Annseraf

AgentLink is a self-hosted bridge for AI agents. This preview runs a native Rust
service with a local dashboard and account management. The engine, dashboard
and identity store run independently of any hosted service or Annseraf account.

## Local setup

On Linux, install Rust 1.85 or newer with Cargo and a C compiler (for bundled
SQLite). Run this from the checkout in an interactive terminal:

```sh
./setup.sh
```

Enter your admin email. Type a temporary password at the hidden prompt or
press Enter to generate one. The generated password is shown once on the
installing terminal. Use a private terminal without session recording.
When setup reports the listening address, open
[http://127.0.0.1:8787/](http://127.0.0.1:8787/), sign in and set a new password.
Then sign in again with the new password.

The server runs in the foreground. Stop it with Ctrl+C. Run the same script
again to rebuild and restart with the existing accounts and state. The
database lives in `.agentlink/agentlink.sqlite3` beside the script by default.
For a separate install, set `AGENTLINK_STATE_DIR` to an absolute path with an
existing parent directory. Use `AGENTLINK_PORT` to change the listening port.
If startup reports an occupied port, stop the other process or use a different
port. Keep the state directory private to the service operator. Stop the
service before copying the database for an offline backup.

The dashboard binds to IPv4 loopback and expects its numeric local address in
the browser. On a remote machine, use SSH local forwarding, keeping the
local and remote ports identical, then open the same numeric loopback URL:

```sh
ssh -N -L 8787:127.0.0.1:8787 your-linux-host
```

Use this preview through loopback or the SSH tunnel. The service uses local
HTTP and has no public ingress or TLS configuration.

## People and sessions

An Admin can add people as Members or Admins, reset passwords, revoke sessions,
and remove or restore access. To restore access, open People and select
**Restore access** on the disabled account. Set a new temporary password and
share it privately. Restoring access keeps the original account and its role.
New, reset, and restored accounts must change their temporary password.
Share temporary passwords privately. Members can use their own account.
A removed account remains in the local database for audit references, and a
transaction prevents removal of the last active Admin.

Passwords are stored as salted Argon2id hashes. The server stores digests of
opaque session tokens. Sessions expire after 12 hours. Password changes, admin
resets and access removal revoke all sessions for the affected person. Account
change events record the operator, target, action and time in SQLite.

### Recover a lost administrator password

From the AgentLink checkout, open an interactive terminal as the installation's
operating system user. Use the same `AGENTLINK_STATE_DIR` as your running
installation if you set a custom path.

```sh
./setup.sh reset-admin admin@example.invalid
```

Replace the example email with your active admin's address. Enter and confirm
a new temporary password at the hidden prompts. Sign in with it and choose
a permanent password. Recovery works while the service is running, including
when this is the only active admin. It revokes that account's existing sessions
and keeps the database, other accounts, and their sessions. SQLite records a
terminal recovery event against the recovered account.

## Verify locally

The smoke test requires Python 3 and a Linux PTY. It starts isolated copies
through the setup script, generates disposable credentials and exercises the
HTTP API through loopback.

```sh
cargo fmt --check
cargo clippy --locked --all-targets --jobs 2 -- -D warnings
python3 tests/smoke.py
```

The test checks first sign-in and password change, repeat setup, role enforcement,
session invalidation after revocation, password reset, access removal and restoration,
terminal-only admin recovery, and concurrent protection of the last active admin. For a manual dashboard pass,
sign in, change the initial password, and use People to create a Member with a
disposable local credential. Sign in as that Member in a separate browser
profile, then revoke their sessions from the Admin profile.

## Bridge roadmap

Bot registration, scoped resource grants, durable 1:1 and opt-in group routing,
approval handling, and the versioned adapter SDK are upcoming. Hermes Agent
and OpenClaw are the first provider verification targets. This preview has no
verified provider round trips. Future managed hosting, tenant administration
and billing belong in a separate control plane.

The bundled mark comes from the official
[Annseraf brand asset](https://annseraf.com/assets/brand/annseraf-mark-navy.svg).

## Optional Cloud enrollment

Set `AGENTLINK_CLOUD_ORIGIN` to the owner's HTTPS Cloud origin before running
setup. Use `AGENTLINK_CLOUD_CA` only for an operator-vetted private CA PEM.
The engine accepts a bare origin and disables redirects and proxy discovery.
In the local dashboard, sign in as an administrator, change any temporary
password, open **Cloud**, verify the displayed origin, enter the workspace's
single-use proof and installation name, and confirm consent. **Refresh status**
shows the latest outcome. Pre-purchase installations can pair.

The engine saves a random installation ID and a separate random credential in
the private local SQLite database before sending the first claim. Protect its
0700 state directory and encrypt backups that include this database. Pending
claims retry after restart with the same values. Success deletes the proof.
Only the installation identifier, name, proof, and dedicated enrollment
credential go to the configured Cloud endpoint. Refresh uses bearer auth.
Requests have a three-second connection deadline and an eight-second total
deadline. Failures disable hosted access and retry with backoff capped at two
minutes. An expired entitlement, changed origin, or incompatible response
also disables hosted access. Local sign-in, accounts, and dashboard keep working.

Use **Disconnect this installation** to remove the local proof and credential,
including while offline. The Cloud owner separately revokes the registration
in its workspace. A denied refresh clears the engine credential. To rotate or
re-pair, revoke in Cloud, disconnect locally, then use a fresh proof from the
same workspace. The stable installation ID survives. Consent, disconnect and
state transitions are recorded as metadata in the local `cloud_events` table.
