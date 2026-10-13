use super::*;

fn hdr(object: u32, opcode: u16, size: u16) -> [u8; 8] {
    Header {
        object,
        opcode,
        size,
    }
    .encode()
}

#[test]
fn header_roundtrip() {
    let h = Header {
        object: 1,
        opcode: 1,
        size: 12,
    };
    assert_eq!(Header::parse(&h.encode()).unwrap(), h);
}

#[test]
fn header_needs_eight_bytes() {
    assert_eq!(Header::parse(&[0u8; 7]), Err(WireError::Truncated));
    assert_eq!(Header::parse(&[]), Err(WireError::Truncated));
}

#[test]
fn size_below_header_is_refused() {
    // Unchecked, `size - 8` would underflow into a huge length.
    for bad in [0u16, 1, 4, 7] {
        assert_eq!(
            Header::parse(&hdr(1, 0, bad)),
            Err(WireError::BadSize(bad)),
            "size {bad} should be refused"
        );
    }
}

#[test]
fn unaligned_size_is_refused() {
    for bad in [9u16, 10, 11, 13] {
        assert_eq!(Header::parse(&hdr(1, 0, bad)), Err(WireError::BadSize(bad)));
    }
}

#[test]
fn oversized_message_is_refused() {
    let too_big = (MAX_MESSAGE_LEN + 4) as u16;
    assert_eq!(
        Header::parse(&hdr(1, 0, too_big)),
        Err(WireError::BadSize(too_big))
    );
    // The boundary itself is legal.
    assert!(Header::parse(&hdr(1, 0, MAX_MESSAGE_LEN as u16)).is_ok());
}

#[test]
fn pad4_rounds_up() {
    assert_eq!(pad4(0), Some(0));
    assert_eq!(pad4(1), Some(4));
    assert_eq!(pad4(4), Some(4));
    assert_eq!(pad4(5), Some(8));
    assert_eq!(pad4(usize::MAX), None);
}

#[test]
fn reads_words() {
    let body = [1u32, 0xFFFF_FFFF]
        .iter()
        .flat_map(|v| v.to_ne_bytes())
        .collect::<Vec<u8>>();
    let mut r = ArgReader::new(&body);
    assert_eq!(r.u32().unwrap(), 1);
    assert_eq!(r.u32().unwrap(), 0xFFFF_FFFF);
    assert!(r.is_empty());
    assert_eq!(r.u32(), Err(WireError::ArgOverrun));
}

#[test]
fn reads_padded_string() {
    // "wl_shm" is 6 bytes + NUL = 7 declared, padded to 8.
    let mut body = 7u32.to_ne_bytes().to_vec();
    body.extend_from_slice(b"wl_shm\0\0");
    let mut r = ArgReader::new(&body);
    assert_eq!(r.string().unwrap(), Some("wl_shm"));
    assert!(r.is_empty());
}

#[test]
fn null_string_is_none() {
    let body = 0u32.to_ne_bytes().to_vec();
    let mut r = ArgReader::new(&body);
    assert_eq!(r.string().unwrap(), None);
}

#[test]
fn unterminated_string_is_refused() {
    // Declares 4 bytes but the fourth is not a NUL.
    let mut body = 4u32.to_ne_bytes().to_vec();
    body.extend_from_slice(b"abcd");
    let mut r = ArgReader::new(&body);
    assert_eq!(r.string(), Err(WireError::UnterminatedString));
}

#[test]
fn interior_nul_is_refused() {
    let mut body = 7u32.to_ne_bytes().to_vec();
    body.extend_from_slice(b"wl\0shm\0\0");
    let mut r = ArgReader::new(&body);
    assert_eq!(r.string(), Err(WireError::InteriorNul));
}

#[test]
fn non_utf8_is_refused() {
    let mut body = 4u32.to_ne_bytes().to_vec();
    body.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0x00]);
    let mut r = ArgReader::new(&body);
    assert_eq!(r.string(), Err(WireError::NotUtf8));
}

#[test]
fn overlong_string_is_refused() {
    // Declared length far beyond what was sent.
    let body = 0xFFFF_FF00u32.to_ne_bytes().to_vec();
    let mut r = ArgReader::new(&body);
    assert_eq!(r.string(), Err(WireError::ArgOverrun));
}

#[test]
fn overlong_array_is_refused() {
    let body = 0xFFFF_FF00u32.to_ne_bytes().to_vec();
    let mut r = ArgReader::new(&body);
    assert_eq!(r.array(), Err(WireError::ArgOverrun));
}

#[test]
fn reads_padded_array() {
    let mut body = 5u32.to_ne_bytes().to_vec();
    body.extend_from_slice(&[1, 2, 3, 4, 5, 0, 0, 0]);
    let mut r = ArgReader::new(&body);
    assert_eq!(r.array().unwrap(), &[1, 2, 3, 4, 5]);
    assert!(r.is_empty());
}

#[test]
fn writer_output_reads_back() {
    // wl_display.error(object_id, code, message)
    let msg = MessageWriter::new(1, 0)
        .u32(7)
        .u32(3)
        .string("no")
        .finish()
        .unwrap();
    let h = Header::parse(&msg).unwrap();
    assert_eq!(h.object, 1);
    assert_eq!(h.opcode, 0);
    assert_eq!(h.size as usize, msg.len());

    let mut r = ArgReader::new(&msg[HEADER_LEN..]);
    assert_eq!(r.u32().unwrap(), 7);
    assert_eq!(r.u32().unwrap(), 3);
    assert_eq!(r.string().unwrap(), Some("no"));
    assert!(r.is_empty());
}

#[test]
fn writer_output_is_aligned() {
    for s in ["", "a", "ab", "abc", "abcd", "abcde"] {
        let msg = MessageWriter::new(1, 0).string(s).finish().unwrap();
        assert_eq!(msg.len() % 4, 0, "string {s:?} produced {} bytes", msg.len());
        let mut r = ArgReader::new(&msg[HEADER_LEN..]);
        assert_eq!(r.string().unwrap(), Some(s));
    }
}

#[test]
fn writer_refuses_oversized_message() {
    let huge = "x".repeat(MAX_MESSAGE_LEN);
    assert!(MessageWriter::new(1, 0).string(&huge).finish().is_none());
}

#[test]
fn server_id_base_splits_ranges() {
    assert_eq!(SERVER_ID_BASE, 0xFF00_0000);
    const _: () = assert!(1 < SERVER_ID_BASE && 0xFEFF_FFFF < SERVER_ID_BASE);
}
