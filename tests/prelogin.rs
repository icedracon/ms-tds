use ms_tds::prelogin::{encryption, PreLogin, Version};

#[test]
fn prelogin_roundtrip() {
    let mut p = PreLogin::new_default();
    p.version = Version {
        major: 15,
        minor: 0,
        build: 4235,
        subbuild: 2,
    };
    p.encryption = encryption::REQ;
    p.instance = b"MSSQLSERVER\0".to_vec();
    p.thread_id = 0x1234;
    p.mars = true;
    let bytes = p.encode();

    // Index is 5 entries × 5 bytes + 1 terminator = 26 bytes.
    assert_eq!(bytes[25], 0xff, "terminator not at expected position");

    let back = PreLogin::decode(&bytes).unwrap();
    assert_eq!(back.version, p.version);
    assert_eq!(back.encryption, encryption::REQ);
    assert_eq!(back.instance, p.instance);
    assert_eq!(back.thread_id, p.thread_id);
    assert!(back.mars);
}

#[test]
fn prelogin_default_encodes_and_decodes() {
    let bytes = PreLogin::new_default().encode();
    let back = PreLogin::decode(&bytes).unwrap();
    assert_eq!(back.version, Version::CLIENT);
    assert_eq!(back.encryption, encryption::OFF);
    assert!(!back.mars);
}

#[test]
fn prelogin_decode_rejects_truncated_index() {
    let bad = [0x00u8, 0x00]; // option type 0 but no offset/length
    assert!(PreLogin::decode(&bad).is_err());
}
