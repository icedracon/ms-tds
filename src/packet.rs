//! TDS packet framing (MS-TDS §2.2.3).
//!
//! Every TDS message is a stream of 8-byte-header packets. Header fields are
//! big-endian (network order) — the sole big-endian corner of the protocol;
//! payloads that follow are little-endian.
//!
//! ```text
//!   0        1        2        3        4        5        6        7
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! | Type   | Status |   Length (BE)   |    SPID (BE)    |PktId   | Window |
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! ```

use crate::{Error, Result};

pub const HEADER_LEN: usize = 8;
pub const DEFAULT_PACKET_SIZE: u16 = 4096;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    SqlBatch = 0x01,
    // 0x02 legacy pre-TDS7 login — unused.
    Rpc = 0x03,
    TabularResult = 0x04,
    Attention = 0x06,
    BulkLoad = 0x07,
    FederatedAuthToken = 0x08,
    TransactionMgr = 0x0e,
    Login7 = 0x10,
    Sspi = 0x11,
    PreLogin = 0x12,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0x01 => Self::SqlBatch,
            0x03 => Self::Rpc,
            0x04 => Self::TabularResult,
            0x06 => Self::Attention,
            0x07 => Self::BulkLoad,
            0x08 => Self::FederatedAuthToken,
            0x0e => Self::TransactionMgr,
            0x10 => Self::Login7,
            0x11 => Self::Sspi,
            0x12 => Self::PreLogin,
            _ => return Err(Error::InvalidPacketType(v)),
        })
    }
}

/// Status bit flags in the second header byte.
pub mod status {
    pub const NORMAL: u8 = 0x00;
    pub const END_OF_MESSAGE: u8 = 0x01;
    pub const IGNORE: u8 = 0x02;
    pub const RESET_CONNECTION: u8 = 0x08;
    pub const RESET_CONNECTION_SKIP_TRAN: u8 = 0x10;
}

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub ptype: PacketType,
    pub status: u8,
    pub length: u16,
    pub spid: u16,
    pub packet_id: u8,
    pub window: u8,
}

impl Header {
    pub fn new(ptype: PacketType, status: u8, length: u16, packet_id: u8) -> Self {
        Self {
            ptype,
            status,
            length,
            spid: 0,
            packet_id,
            window: 0,
        }
    }

    pub fn encode(&self, out: &mut [u8; HEADER_LEN]) {
        out[0] = self.ptype as u8;
        out[1] = self.status;
        out[2..4].copy_from_slice(&self.length.to_be_bytes());
        out[4..6].copy_from_slice(&self.spid.to_be_bytes());
        out[6] = self.packet_id;
        out[7] = self.window;
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(Error::ShortRead {
                expected: HEADER_LEN,
                got: buf.len(),
            });
        }
        Ok(Self {
            ptype: PacketType::from_u8(buf[0])?,
            status: buf[1],
            length: u16::from_be_bytes([buf[2], buf[3]]),
            spid: u16::from_be_bytes([buf[4], buf[5]]),
            packet_id: buf[6],
            window: buf[7],
        })
    }
}

/// Segment `payload` into one or more packets, each ≤ `packet_size` bytes.
/// `packet_id` starts at 1 and wraps mod 256. Every packet except the last
/// carries `status = NORMAL`; the last one carries `END_OF_MESSAGE`.
///
/// If `payload` is empty, a single header-only packet is emitted with
/// `END_OF_MESSAGE`.
pub fn frame(ptype: PacketType, payload: &[u8], packet_size: u16) -> Vec<Vec<u8>> {
    let max_body = (packet_size as usize).saturating_sub(HEADER_LEN).max(1);
    let mut out = Vec::new();
    if payload.is_empty() {
        let hdr = Header::new(ptype, status::END_OF_MESSAGE, HEADER_LEN as u16, 1);
        let mut hbuf = [0u8; HEADER_LEN];
        hdr.encode(&mut hbuf);
        out.push(hbuf.to_vec());
        return out;
    }
    let chunks: Vec<&[u8]> = payload.chunks(max_body).collect();
    let last = chunks.len() - 1;
    for (i, chunk) in chunks.iter().enumerate() {
        let stat = if i == last {
            status::END_OF_MESSAGE
        } else {
            status::NORMAL
        };
        let hdr = Header::new(
            ptype,
            stat,
            (HEADER_LEN + chunk.len()) as u16,
            ((i + 1) & 0xff) as u8,
        );
        let mut hbuf = [0u8; HEADER_LEN];
        hdr.encode(&mut hbuf);
        let mut pkt = Vec::with_capacity(HEADER_LEN + chunk.len());
        pkt.extend_from_slice(&hbuf);
        pkt.extend_from_slice(chunk);
        out.push(pkt);
    }
    out
}
