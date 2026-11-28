# Standalone bridge architecture and capability matrix

The Rust engine owns local identity, registrations, grants, message state, and
the dashboard. The managed service owns tenant administration, billing and
hosting operations in a separate control plane. Standalone setup uses local
SQLite and loopback by default and requires no hosted account. A Cloud pairing
or entitlement must never serve as a local message grant. The adapter contract
in this branch changes no Cloud API, enrollment token, or release interface.

| Integration | Tenancy and authority | Planned transport | Text and replies | Native threads, groups, proactive send, invocation, tools and attachments |
| --- | --- | --- | --- | --- |
| SDK v1 reference | Synthetic registration, local child process; no production authentication | UTF-8 newline-delimited JSON over stdio | Fixture echo with correlation and exact reply binding, covered by the contract check | Thread ID preservation only. Other behavior unverified or out of scope |
| Hermes Agent | Dedicated gateway install and dedicated plugin registration in a test workspace | Thin Python gateway plugin using `ctx.register_platform`, native inbound events and adapter outbound sends | Planned in both directions. Version and runtime round trip unverified | Record native threads and groups separately. Remaining capabilities out of scope for text pilot |
| OpenClaw | Dedicated test gateway and channel account with native sender/account policy applied | Thin TypeScript Channel Plugin using native inbound dispatch and outbound delivery | Planned in both directions. Version and runtime round trip unverified | Verify DMs and threads separately. Other capabilities out of scope for text pilot |
| Private Campfire bridge | Dedicated room, bot-specific ingress token, employee grants, and restricted upstream key | HTTPS webhooks and fixed-room HTTP replies | Synthetic bridge checks tracked in the private service. Production provider support unverified | Separate private pilot and rollout; no standalone SDK conformance claim |

Provider interface references are the [Hermes gateway adapter guide](https://hermes-agent.nousresearch.com/docs/developer-guide/adding-platform-adapters)
and [OpenClaw Channel Plugin SDK guide](https://docs.openclaw.ai/plugins/sdk-channel-plugins).
Record the package version, immutable source revision, configuration and scope,
test workspace, tested direction, and evidence before declaring native support.
Version 1 of the local JSON contract is independent of any provider version.
Keep provider credentials with the relevant registration and out of messages,
error strings, audit records and screenshots.

## Routing and trust boundaries

1. The provider shim authenticates the upstream event and resolves its
   provider account, room, thread, sender and event ID. Map those opaque values
   to stable engine IDs within that registration. Never derive a destination
   from message text or trust the tenant/room claimed by an inbound envelope.
2. The engine checks active registration, sender permission and explicit
   destination selection before persisting work. A future group registration
   needs explicit opt-in and a fixed recipient set per accepted event. A room
   change, grant revocation or consent withdrawal invalidates stale work.
3. Persist the original route and the provider event ID for deduplication.
   Recheck current registration and grant before dispatch and again before
   delivery. Correlation and exact scope matching bind the reply to the
   persisted route. They supplement authenticated adapter identity.
4. Report delivery only after the originating transport confirms it. Hold
   ambiguous mutations for reconciliation. A retry needs either a provider
   idempotency guarantee or a proven read-only operation. Audit metadata such
   as transition, time and reference ID. Avoid recording payloads or secrets.

Steps 1–4 describe requirements for an engine runtime. The SDK slice supplies
typed messages and reply validation. It does not register processes, grant
permissions, persist work or dispatch to providers.

## Implementation and deployment boundaries

Use the standalone Rust implementation and provider-native shims. The private
Campfire bridge supplies patterns worth reviewing, including fixed destinations,
durable state and uncertainty handling. Copying its private code into OSS
requires a rights and portability review. A hosted service can operate the
standalone engine after isolation and enrollment review. Its data, secrets and
deployment configuration stay separate.

Build and test from an exact reviewed commit. Use disposable state for native
setup and adapter fixtures. Verify Linux x86-64 and Pi ARM64, confirm loopback
binding, and rerun setup to verify that state and the administrator survive.
Provider integration, live round trips and supported-version claims await the
pinned pilot environments.
