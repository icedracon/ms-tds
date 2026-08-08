use ms_tds::packet::{frame, status, Header, PacketType, DEFAULT_PACKET_SIZE, HEADER_LEN};

#[test]
fn header_roundtrip() {
    let h = Header::new(PacketType::PreLogin, status::END_OF_MESSAGE, 42, 7);
    let mut buf = [0u8; HEADER_LEN];
    h.encode(&mut buf);
    assert_eq!(buf[0], PacketType::PreLogin as u8);
    assert_eq!(buf[1], status::END_OF_MESSAGE);
    assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 42);
    assert_eq!(buf[6], 7);
    let r = Header::decode(&buf).unwrap();
    assert_eq!(r.ptype, PacketType::PreLogin);
    assert_eq!(r.status, status::END_OF_MESSAGE);
    assert_eq!(r.length, 42);
    assert_eq!(r.packet_id, 7);
}

#[test]
fn frame_segments_across_packets() {
    let body: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
    let packets = frame(PacketType::SqlBatch, &body, 4096);
    // 10_000 / (4096 - 8) = 3 packets (last one small).
    assert!(
        packets.len() >= 3,
        "expected >=3 packets, got {}",
        packets.len()
    );
    let mut re = Vec::new();
    for (i, pkt) in packets.iter().enumerate() {
        let hdr = Header::decode(&pkt[..HEADER_LEN]).unwrap();
        assert_eq!(hdr.ptype, PacketType::SqlBatch);
        assert_eq!(hdr.length as usize, pkt.len());
        if i + 1 == packets.len() {
            assert_eq!(hdr.status, status::END_OF_MESSAGE);
        } else {
            assert_eq!(hdr.status, status::NORMAL);
        }
        re.extend_from_slice(&pkt[HEADER_LEN..]);
    }
    assert_eq!(re, body);
}

#[test]
fn frame_empty_payload_still_terminates() {
    let packets = frame(PacketType::PreLogin, &[], DEFAULT_PACKET_SIZE);
    assert_eq!(packets.len(), 1);
    let hdr = Header::decode(&packets[0][..HEADER_LEN]).unwrap();
    assert_eq!(hdr.status, status::END_OF_MESSAGE);
    assert_eq!(hdr.length as usize, HEADER_LEN);
    assert_eq!(hdr.ptype, PacketType::PreLogin);
}

#[test]
fn header_decode_rejects_short_buffer() {
    let short = [0u8; 4];
    assert!(Header::decode(&short).is_err());
}

#[test]
fn header_decode_rejects_unknown_type() {
    let mut buf = [0u8; HEADER_LEN];
    buf[0] = 0x2a; // not a real TDS packet type
    buf[2..4].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
    assert!(Header::decode(&buf).is_err());
}
