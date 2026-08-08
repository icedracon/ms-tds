//! PreLogin token stream (MS-TDS §2.2.6.5). Client and server both send this shape.
//!
//! Index list: `[option_type(1) offset(2 BE) length(2 BE)]*` then `0xFF` terminator,
//! followed by the concatenated data blob referenced by the entries.

use crate::{Error, Result};

pub const VERSION: u8 = 0x00;
pub const ENCRYPTION: u8 = 0x01;
pub const INSTOPT: u8 = 0x02;
pub const THREADID: u8 = 0x03;
pub const MARS: u8 = 0x04;
pub const TRACEID: u8 = 0x05;
pub const FEDAUTHREQUIRED: u8 = 0x06;
pub const NONCEOPT: u8 = 0x07;
pub const TERMINATOR: u8 = 0xff;

pub mod encryption {
    /// Client offers encryption; server may accept or refuse.
    pub const OFF: u8 = 0x00;
    /// Server requires encryption of the login only.
    pub const ON: u8 = 0x01;
    /// Server does not support encryption.
    pub const NOT_SUP: u8 = 0x02;
    /// Server requires full-session encryption.
    pub const REQ: u8 = 0x03;
    /// Client indicates no cert available.
    pub const CLIENT_CERT_OFF: u8 = 0x80;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub build: u16,
    pub subbuild: u16,
}

impl Version {
    pub const CLIENT: Self = Self {
        major: 9,
        minor: 0,
        build: 0,
        subbuild: 0,
    };

    pub fn encode(&self) -> [u8; 6] {
        let mut b = [0u8; 6];
        b[0] = self.major;
        b[1] = self.minor;
        b[2..4].copy_from_slice(&self.build.to_be_bytes());
        b[4..6].copy_from_slice(&self.subbuild.to_be_bytes());
        b
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::CLIENT
    }
}

/// Options a client wants to negotiate before login.
#[derive(Debug, Clone)]
pub struct PreLogin {
    pub version: Version,
    pub encryption: u8,
    /// ASCII, NUL-terminated (per spec — a bare `[0]` is the "no instance" case).
    pub instance: Vec<u8>,
    pub thread_id: u32,
    pub mars: bool,
}

impl Default for PreLogin {
    fn default() -> Self {
        Self {
            version: Version::CLIENT,
            encryption: encryption::OFF,
            instance: vec![0],
            thread_id: 0,
            mars: false,
        }
    }
}

impl PreLogin {
    pub fn new_default() -> Self {
        Self::default()
    }

    pub fn encode(&self) -> Vec<u8> {
        // Five options fixed: VERSION(6) ENCRYPTION(1) INSTOPT(n) THREADID(4) MARS(1).
        let entries: [(u8, u16); 5] = [
            (VERSION, 6),
            (ENCRYPTION, 1),
            (INSTOPT, self.instance.len() as u16),
            (THREADID, 4),
            (MARS, 1),
        ];
        let index_len = 5 * entries.len() + 1;
        let data_len = 6 + 1 + self.instance.len() + 4 + 1;
        let mut out = Vec::with_capacity(index_len + data_len);
        let mut off = index_len as u16;
        for (t, l) in entries {
            out.push(t);
            out.extend_from_slice(&off.to_be_bytes());
            out.extend_from_slice(&l.to_be_bytes());
            off += l;
        }
        out.push(TERMINATOR);
        // Data segment
        out.extend_from_slice(&self.version.encode());
        out.push(self.encryption);
        out.extend_from_slice(&self.instance);
        out.extend_from_slice(&self.thread_id.to_be_bytes());
        out.push(self.mars as u8);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut pl = Self::default();
        pl.instance.clear();
        let mut i = 0;
        loop {
            if i >= buf.len() {
                return Err(Error::Protocol("prelogin: truncated index"));
            }
            let t = buf[i];
            i += 1;
            if t == TERMINATOR {
                break;
            }
            if i + 4 > buf.len() {
                return Err(Error::Protocol("prelogin: truncated entry"));
            }
            let off = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
            let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
            i += 4;
            if off.saturating_add(len) > buf.len() {
                return Err(Error::Protocol("prelogin: data OOB"));
            }
            let data = &buf[off..off + len];
            match t {
                VERSION if data.len() >= 6 => {
                    pl.version = Version {
                        major: data[0],
                        minor: data[1],
                        build: u16::from_be_bytes([data[2], data[3]]),
                        subbuild: u16::from_be_bytes([data[4], data[5]]),
                    };
                }
                ENCRYPTION if !data.is_empty() => pl.encryption = data[0],
                INSTOPT => pl.instance.extend_from_slice(data),
                THREADID if data.len() >= 4 => {
                    pl.thread_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                }
                MARS if !data.is_empty() => pl.mars = data[0] != 0,
                // Unknown / future options — ignore.
                _ => {}
            }
        }
        Ok(pl)
    }
}
