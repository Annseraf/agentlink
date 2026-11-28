//! Exercise the production binary and TLS client against a disposable peer.
#[test]
fn local_admin_cloud_enrollment() {
    let result = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/cloud_fixture.py"
        ))
        .arg(env!("CARGO_BIN_EXE_agentlink"))
        .status()
        .expect("Python 3 is required for the Cloud fixture");
    assert!(result.success());
}
