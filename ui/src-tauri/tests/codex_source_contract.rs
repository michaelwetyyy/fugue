#[allow(dead_code)]
#[path = "../src/codex_source.rs"]
mod codex_source;

#[test]
fn source_bridge_exposes_closed_public_errors() {
    assert_eq!(
        codex_source::CodexSourceError::DeliveryUnknown.public_message(),
        "Codex message delivery is uncertain"
    );
}

#[test]
#[ignore = "requires the configured local Codex App Server"]
fn configured_source_lists_metadata_without_turns() {
    let mut source = codex_source::CodexSourceClient::connect_live().unwrap();
    let page = source.list_threads(None, 1).unwrap();
    assert!(page.data.len() <= 1);
    if let Some(thread) = page.data.first() {
        let metadata = source.read_thread_metadata(&thread.id).unwrap();
        assert_eq!(metadata.id, thread.id);
    }
}
