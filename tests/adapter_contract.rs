use std::io::Write;
use std::process::{Command, Stdio};

use agentlink::adapter::{Capability, ContractError, Descriptor, TextEnvelope};
use serde_json::{Value, json};

fn message() -> Value {
    json!({
        "version": 1,
        "binding": {"tenant": "dev", "adapter": "fixture", "room": "room-1", "thread": "thread-1"},
        "correlation_id": "handoff-1",
        "text": "Hello from a synthetic conversation"
    })
}

#[test]
fn reply_must_match_every_binding_field_and_correlation() {
    let source = message();
    let original = serde_json::from_value::<TextEnvelope>(source.clone()).unwrap();
    for field in ["tenant", "adapter", "room", "thread"] {
        let mut other = source.clone();
        other["binding"][field] = json!("other");
        let reply: TextEnvelope = serde_json::from_value(other).unwrap();
        assert_eq!(
            reply.validate_reply(&original),
            Err(ContractError::BindingMismatch)
        );
    }
    let mut other = source;
    other["correlation_id"] = json!("other");
    let reply: TextEnvelope = serde_json::from_value(other).unwrap();
    assert_eq!(
        reply.validate_reply(&original),
        Err(ContractError::BindingMismatch)
    );
}

#[test]
fn reference_adapter_negotiates_and_round_trips_text() {
    let mut child = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/adapter/reference.py"
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let source = message();
    let mut newer = source.clone();
    newer["version"] = json!(2);
    let mut oversized = source.clone();
    oversized["text"] = json!("é".repeat(8193));
    for request in [json!({"describe": true}), source.clone(), newer, oversized] {
        writeln!(input, "{request}").unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 4);
    let descriptor: Descriptor = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(descriptor.require(Capability::ConversationText), Ok(()));
    assert_eq!(
        descriptor.require(Capability::AgentInvocation),
        Err(ContractError::UnsupportedCapability)
    );
    assert_eq!(
        descriptor.require(Capability::Tools),
        Err(ContractError::UnsupportedCapability)
    );
    let original: TextEnvelope = serde_json::from_value(source).unwrap();
    let reply: TextEnvelope = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(reply.validate_reply(&original), Ok(()));
    assert_eq!(reply.text, original.text);
    assert_eq!(
        serde_json::from_str::<Value>(lines[2]).unwrap(),
        json!({"error": "unsupported_version"})
    );
    assert_eq!(
        serde_json::from_str::<Value>(lines[3]).unwrap(),
        json!({"error": "invalid_envelope"})
    );
}
