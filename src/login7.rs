//! Login7 packet (MS-TDS §2.2.6.4). Strings are UTF-16LE; the password field uses
//! the trivial "nibble-swap ^ 0xA5" obfuscation.
//!
//! Layout:
//! ```text
//!   [0..36]   Fixed header (len, tds_ver, packet_size, prog_ver, pid, conn_id, flags*, tz, lcid)
//!   [36..94]  9 OL pairs (36) + ClientID (6) + 3 OL pairs (12) + cbSSPILong (4)
//!   [94..]    Variable data blob (UTF-16LE strings, then SSPI blob)
//! ```

/// TDS 7.4 protocol version as it appears on the wire (little-endian u32).
pub const TDS_74: u32 = 0x74000004;

pub const DEFAULT_PACKET_SIZE: u32 = 4096;

/// OptionFlags1 bits (MS-TDS §2.2.6.4).
pub mod flags1 {
    pub const INIT_DB_FATAL: u8 = 0x20;
    pub const SET_LANG_ON: u8 = 0x40;
    pub const INIT_LANG_FATAL: u8 = 0x80;
}

pub mod flags2 {
    pub const ODBC_ON: u8 = 0x02;
    pub const INTEGRATED_SECURITY: u8 = 0x80;
}

pub mod type_flags {
    pub const SQL_DFLT: u8 = 0x00;
    pub const OLEDB_ON: u8 = 0x10;
    pub const READ_ONLY_INTENT: u8 = 0x20;
}

fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// Login7 password obfuscation: XOR with 0xA5 then swap nibbles, per UTF-16LE byte.
pub fn obfuscate_password(s: &str) -> Vec<u8> {
    utf16le(s)
        .into_iter()
        .map(|b| {
            let x = b ^ 0xa5;
            ((x & 0x0f) << 4) | ((x & 0xf0) >> 4)
        })
        .collect()
}

#[derive(Debug, Default, Clone)]
pub struct Login7 {
    pub host: String,
    pub user: String,
    pub password: String,
    pub app: String,
    pub server: String,
    pub library: String,
    pub language: String,
    pub database: String,
    pub client_id: [u8; 6],
    pub packet_size: u32,
    pub client_pid: u32,
    /// If set, `INTEGRATED_SECURITY` is enabled and the blob (NTLM Type 1) rides in
    /// the ibSSPI slot. `user` / `password` are ignored by the server in that case.
    pub sspi: Option<Vec<u8>>,
}

impl Login7 {
    pub fn new_sspi(host: &str, server: &str, database: &str, sspi_blob: Vec<u8>) -> Self {
        Self {
            host: host.to_string(),
            server: server.to_string(),
            database: database.to_string(),
            app: "ms-tds".to_string(),
            library: "ms-tds".to_string(),
            packet_size: DEFAULT_PACKET_SIZE,
            client_pid: std::process::id(),
            sspi: Some(sspi_blob),
            ..Default::default()
        }
    }

    pub fn new_sql(host: &str, server: &str, database: &str, user: &str, password: &str) -> Self {
        Self {
            host: host.to_string(),
            user: user.to_string(),
            password: password.to_string(),
            server: server.to_string(),
            database: database.to_string(),
            app: "ms-tds".to_string(),
            library: "ms-tds".to_string(),
            packet_size: DEFAULT_PACKET_SIZE,
            client_pid: std::process::id(),
            ..Default::default()
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        // Layout per MS-TDS 2.2.6.4:
        //   Fixed 36-byte header,
        //   9 OL pairs (4 each) for HostName..Database = 36,
        //   ClientID = 6,
        //   3 OL pairs for SSPI / AtchDBFile / ChangePassword = 12,
        //   cbSSPILong = 4.
        // Total = 36 + 36 + 6 + 12 + 4 = 94.
        const FIXED: usize = 36;
        const OL_BLOCK: usize = 58;
        const HEADER: usize = FIXED + OL_BLOCK;

        let host = utf16le(&self.host);
        let user = utf16le(&self.user);
        let pwd = obfuscate_password(&self.password);
        let app = utf16le(&self.app);
        let server = utf16le(&self.server);
        let library = utf16le(&self.library);
        let language = utf16le(&self.language);
        let database = utf16le(&self.database);
        let sspi_ref: &[u8] = self.sspi.as_deref().unwrap_or(&[]);

        // Emit variable blob first, capturing each field's absolute offset.
        let mut data = Vec::new();
        let push_field = |data: &mut Vec<u8>, bytes: &[u8]| {
            let off = HEADER + data.len();
            data.extend_from_slice(bytes);
            off
        };
        let host_off = push_field(&mut data, &host);
        let user_off = push_field(&mut data, &user);
        let pwd_off = push_field(&mut data, &pwd);
        let app_off = push_field(&mut data, &app);
        let server_off = push_field(&mut data, &server);
        // Extension slot unused in classic layout — advertise (0,0).
        let library_off = push_field(&mut data, &library);
        let language_off = push_field(&mut data, &language);
        let database_off = push_field(&mut data, &database);
        let sspi_off = push_field(&mut data, sspi_ref);

        let total_len = (HEADER + data.len()) as u32;

        let mut out = Vec::with_capacity(HEADER + data.len());
        // Fixed 36-byte header
        out.extend_from_slice(&total_len.to_le_bytes());
        out.extend_from_slice(&TDS_74.to_le_bytes());
        out.extend_from_slice(&self.packet_size.to_le_bytes());
        out.extend_from_slice(&0x0700_0000u32.to_le_bytes()); // ClientProgVer
        out.extend_from_slice(&self.client_pid.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // ConnectionID
        let mut of2 = flags2::ODBC_ON;
        if self.sspi.is_some() {
            of2 |= flags2::INTEGRATED_SECURITY;
        }
        out.push(flags1::INIT_DB_FATAL | flags1::SET_LANG_ON | flags1::INIT_LANG_FATAL);
        out.push(of2);
        out.push(type_flags::SQL_DFLT);
        out.push(0); // OptionFlags3
        out.extend_from_slice(&0i32.to_le_bytes()); // ClientTimeZone
        out.extend_from_slice(&0x0000_0409u32.to_le_bytes()); // ClientLCID = en-US

        // OffsetLength block — each entry is (u16 offset, u16 char-count).
        fn ol(out: &mut Vec<u8>, off: usize, char_count: usize) {
            out.extend_from_slice(&(off as u16).to_le_bytes());
            out.extend_from_slice(&(char_count as u16).to_le_bytes());
        }
        ol(&mut out, host_off, self.host.encode_utf16().count());
        ol(&mut out, user_off, self.user.encode_utf16().count());
        ol(&mut out, pwd_off, self.password.encode_utf16().count());
        ol(&mut out, app_off, self.app.encode_utf16().count());
        ol(&mut out, server_off, self.server.encode_utf16().count());
        // Extension pointer — (offset, length) = (0, 0) since unused.
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        ol(&mut out, library_off, self.library.encode_utf16().count());
        ol(&mut out, language_off, self.language.encode_utf16().count());
        ol(&mut out, database_off, self.database.encode_utf16().count());
        out.extend_from_slice(&self.client_id);
        // SSPI is byte-length, not char count.
        out.extend_from_slice(&(sspi_off as u16).to_le_bytes());
        let sspi_short = if sspi_ref.len() > 0xffff {
            0u16
        } else {
            sspi_ref.len() as u16
        };
        out.extend_from_slice(&sspi_short.to_le_bytes());
        // AtchDBFile — zero.
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        // ChangePassword — zero.
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        // cbSSPILong — 4-byte fallback for SSPI blobs > 64k.
        let sspi_long = if sspi_ref.len() > 0xffff {
            sspi_ref.len() as u32
        } else {
            0
        };
        out.extend_from_slice(&sspi_long.to_le_bytes());

        debug_assert_eq!(out.len(), HEADER, "fixed+OL block must be 94 bytes");
        out.extend_from_slice(&data);
        out
    }
}
