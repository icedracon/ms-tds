use ms_tds::login7::{obfuscate_password, Login7, TDS_74};

#[test]
fn login7_total_len_matches_encoded_size() {
    let l = Login7::new_sspi("HOST", "sql01", "master", vec![0xaa, 0xbb, 0xcc, 0xdd]);
    let bytes = l.encode();
    let total = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    assert_eq!(
        total,
        bytes.len(),
        "advertised total_len {} != actual {}",
        total,
        bytes.len()
    );
    let tds = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    assert_eq!(tds, TDS_74);
    // Fixed header + OL block is 94 bytes; data comes after.
    assert!(bytes.len() > 94);
    // SSPI blob should appear verbatim in the data segment.
    let sspi = &[0xaa, 0xbb, 0xcc, 0xdd];
    assert!(
        bytes.windows(4).any(|w| w == sspi),
        "SSPI blob not found in encoded Login7"
    );
}

#[test]
fn login7_password_obfuscation_matches_and_plaintext_absent() {
    let l = Login7::new_sql("HOST", "sql01", "master", "sa", "P@ssw0rd");
    let bytes = l.encode();
    let raw: Vec<u8> = "P@ssw0rd"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let obf = obfuscate_password("P@ssw0rd");
    assert!(
        bytes.windows(obf.len()).any(|w| w == obf),
        "obfuscated password not found: expected {:02x?}",
        obf
    );
    // Sanity: obfuscation is trivial but plaintext UTF-16LE must NOT leak.
    assert!(
        bytes.windows(raw.len()).all(|w| w != raw),
        "plaintext password bytes leaked into Login7"
    );
}

#[test]
fn login7_integrated_security_flag_set_only_with_sspi() {
    // OptionFlags2 lives at offset 25 in the fixed header (right after ClientPID(20..24)+ConnID(20..24)... let's just check the two variants disagree).
    let with = Login7::new_sspi("H", "S", "", vec![0]).encode();
    let without = Login7::new_sql("H", "S", "", "u", "p").encode();
    // OptionFlags2 is at index 25 (after 4+4+4+4+4+4+1 = 25 → index 25).
    // Fields: totalLen(4) tds(4) pktSize(4) progVer(4) pid(4) connId(4) of1(1) of2(1) ...
    let of2_with = with[25];
    let of2_without = without[25];
    assert_ne!(
        of2_with & 0x80,
        of2_without & 0x80,
        "INTEGRATED_SECURITY bit should differ"
    );
    assert_eq!(of2_with & 0x80, 0x80);
    assert_eq!(of2_without & 0x80, 0x00);
}
