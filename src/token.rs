//! Token stream (MS-TDS §2.2.5). Skeleton reader — recognizes token kinds and
//! their length prefixes so the caller can walk the stream, but does not decode
//! ROW / COLMETADATA yet (that needs the full type-info decoder — future work).

use crate::{Error, Result};

pub mod kind {
    pub const RETURN_STATUS: u8 = 0x79;
    pub const COLMETADATA: u8 = 0x81;
    pub const ORDER: u8 = 0xa9;
    pub const ERROR: u8 = 0xaa;
    pub const INFO: u8 = 0xab;
    pub const LOGIN_ACK: u8 = 0xad;
    pub const RETURN_VALUE: u8 = 0xac;
    pub const ROW: u8 = 0xd1;
    pub const NBC_ROW: u8 = 0xd2;
    pub const ENV_CHANGE: u8 = 0xe3;
    pub const SSPI: u8 = 0xed;
    pub const DONE: u8 = 0xfd;
    pub const DONE_PROC: u8 = 0xfe;
    pub const DONE_IN_PROC: u8 = 0xff;
}

#[derive(Debug, Clone)]
pub enum Token {
    LoginAck {
        interface: u8,
        tds_version: u32,
        program: String,
        ver: u32,
    },
    /// Server-provided SSPI blob (NTLM CHALLENGE / Kerberos AP-REP).
    Sspi(Vec<u8>),
    EnvChange {
        kind: u8,
        new: Vec<u8>,
        old: Vec<u8>,
    },
    Done {
        status: u16,
        cur_cmd: u16,
        row_count: u64,
    },
    Info {
        number: u32,
        state: u8,
        class: u8,
        message: String,
    },
    Error {
        number: u32,
        state: u8,
        class: u8,
        message: String,
    },
    /// Placeholder for tokens we skip over.
    Unknown { kind: u8, body: Vec<u8> },
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let cp: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&cp)
}

/// UTF-16LE with a single-byte character-count prefix.
fn read_b_varchar(buf: &[u8], off: &mut usize) -> Result<String> {
    if *off >= buf.len() {
        return Err(Error::Protocol("b_varchar: truncated len"));
    }
    let n = buf[*off] as usize;
    *off += 1;
    let nb = n * 2;
    if *off + nb > buf.len() {
        return Err(Error::Protocol("b_varchar: truncated body"));
    }
    let s = decode_utf16le(&buf[*off..*off + nb]);
    *off += nb;
    Ok(s)
}

/// UTF-16LE with a 2-byte character-count prefix.
fn read_us_varchar(buf: &[u8], off: &mut usize) -> Result<String> {
    if *off + 2 > buf.len() {
        return Err(Error::Protocol("us_varchar: truncated len"));
    }
    let n = u16::from_le_bytes([buf[*off], buf[*off + 1]]) as usize;
    *off += 2;
    let nb = n * 2;
    if *off + nb > buf.len() {
        return Err(Error::Protocol("us_varchar: truncated body"));
    }
    let s = decode_utf16le(&buf[*off..*off + nb]);
    *off += nb;
    Ok(s)
}

/// Parse the concatenated body of one TDS response (multi-packet payloads already
/// joined) into a `Vec<Token>`. Bails with `Error::Unsupported` on COLMETADATA /
/// ROW / NBCROW — the caller can then fall back to draining what came before.
pub fn parse_all(buf: &[u8]) -> Result<Vec<Token>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < buf.len() {
        let t = buf[off];
        off += 1;
        let tok = match t {
            kind::LOGIN_ACK => {
                if off + 2 > buf.len() {
                    return Err(Error::Protocol("LOGINACK: len"));
                }
                let len = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
                off += 2;
                let end = off
                    .checked_add(len)
                    .ok_or(Error::Protocol("LOGINACK: overflow"))?;
                if end > buf.len() {
                    return Err(Error::Protocol("LOGINACK: body"));
                }
                let mut p = off;
                let interface = buf[p];
                p += 1;
                let tds_version = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
                p += 4;
                let program = read_b_varchar(buf, &mut p)?;
                if p + 4 > end {
                    return Err(Error::Protocol("LOGINACK: ver"));
                }
                let ver = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
                off = end;
                Token::LoginAck {
                    interface,
                    tds_version,
                    program,
                    ver,
                }
            }
            kind::SSPI => {
                if off + 2 > buf.len() {
                    return Err(Error::Protocol("SSPI: len"));
                }
                let len = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
                off += 2;
                let end = off + len;
                if end > buf.len() {
                    return Err(Error::Protocol("SSPI: body"));
                }
                let body = buf[off..end].to_vec();
                off = end;
                Token::Sspi(body)
            }
            kind::ENV_CHANGE => {
                if off + 2 > buf.len() {
                    return Err(Error::Protocol("ENVCHANGE: len"));
                }
                let len = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
                off += 2;
                let end = off + len;
                if end > buf.len() {
                    return Err(Error::Protocol("ENVCHANGE: body"));
                }
                if len == 0 {
                    return Err(Error::Protocol("ENVCHANGE: empty"));
                }
                let kind_byte = buf[off];
                let tok = Token::EnvChange {
                    kind: kind_byte,
                    new: buf[off + 1..end].to_vec(),
                    old: Vec::new(),
                };
                off = end;
                tok
            }
            kind::DONE | kind::DONE_PROC | kind::DONE_IN_PROC => {
                // TDS 7.4+ carries an 8-byte row count → fixed 12-byte body.
                if off + 12 > buf.len() {
                    return Err(Error::Protocol("DONE: short"));
                }
                let status = u16::from_le_bytes([buf[off], buf[off + 1]]);
                let cur_cmd = u16::from_le_bytes([buf[off + 2], buf[off + 3]]);
                let row_count = u64::from_le_bytes([
                    buf[off + 4],
                    buf[off + 5],
                    buf[off + 6],
                    buf[off + 7],
                    buf[off + 8],
                    buf[off + 9],
                    buf[off + 10],
                    buf[off + 11],
                ]);
                off += 12;
                Token::Done {
                    status,
                    cur_cmd,
                    row_count,
                }
            }
            kind::INFO | kind::ERROR => {
                if off + 2 > buf.len() {
                    return Err(Error::Protocol("INFO/ERROR: len"));
                }
                let len = u16::from_le_bytes([buf[off], buf[off + 1]]) as usize;
                off += 2;
                let end = off + len;
                if end > buf.len() {
                    return Err(Error::Protocol("INFO/ERROR: body"));
                }
                let mut p = off;
                if p + 6 > end {
                    return Err(Error::Protocol("INFO/ERROR: short header"));
                }
                let number = u32::from_le_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
                p += 4;
                let state = buf[p];
                p += 1;
                let class = buf[p];
                p += 1;
                let message = read_us_varchar(buf, &mut p)?;
                let _ = p;
                let tok = if t == kind::INFO {
                    Token::Info {
                        number,
                        state,
                        class,
                        message,
                    }
                } else {
                    Token::Error {
                        number,
                        state,
                        class,
                        message,
                    }
                };
                off = end;
                tok
            }
            kind::COLMETADATA | kind::ROW | kind::NBC_ROW => {
                // TODO: full row-decoder — requires TYPE_INFO for every column
                // (variable-length prefixes, COLLATION for VARCHAR, precision/scale
                // for NUMERIC, PLP for text/image/varchar(max)). Not implemented yet.
                return Err(Error::Unsupported(
                    "token stream: ROW/COLMETADATA decoding not implemented",
                ));
            }
            _ => {
                return Err(Error::Unsupported("token stream: unknown token kind"));
            }
        };
        out.push(tok);
    }
    Ok(out)
}
