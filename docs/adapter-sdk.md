# Conversation adapter contract v1

`agentlink::adapter` supplies Rust types and validation for the initial
conversation transport. Tool use and agent invocation are distinct capability
names. Neither is defined by this text protocol.

The local reference process uses Python 3 and reads one UTF-8 JSON object per
line on stdin. It returns one JSON object per line on stdout. Copy
`examples/adapter/reference.py` to any directory and run it with Python 3.
No environment variables, packages or credentials are required.

```sh
printf '%s\n' '{"describe":true}' '{"version":1,"binding":{"tenant":"dev","adapter":"fixture","room":"room-1","thread":null},"correlation_id":"handoff-1","text":"Hello"}' | python3 reference.py
```

The first response advertises version 1 and `conversation_text`. Check the
version and required capability before sending text. The second response
echoes the text and its original binding. A reply must preserve the tenant,
adapter, room, optional thread and correlation ID. The engine must compare
against the request it retained and deliver through the stored destination.

Identifiers are 1–128 ASCII letters, digits, dots, underscores or hyphens.
The optional thread may be absent or null for an unthreaded room. Text is
nonblank and limited to 16 KiB of UTF-8. The reference process ends the session
if a frame exceeds 128 KiB or lacks its newline. Error replies have a single
`error` field with a stable snake-case code. The fixture implements
`unsupported_version` and `invalid_envelope`. The Rust API additionally
reports `unsupported_capability` and `binding_mismatch` during host-side
validation. A future host will own request deadlines and represent elapsed
deadlines with `timeout`.

Run `cargo test --locked --test adapter_contract` to exercise wire negotiation,
text, invalid sizes and reply binding. The fixture has no production adapter
authentication or delivery side effects. Runtime tests for authenticated
sender scope, duplicate suppression, timeout, reconnect and retry require the
engine adapter lifecycle. Native provider conformance and Pi/x86-64 performance
baselines remain separate acceptance work.
