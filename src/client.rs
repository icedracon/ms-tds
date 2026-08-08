//! High-level TDS 7.4 client.
//!
//! STATUS: pre-alpha. `connect` drives real I/O — PreLogin, and (if the server
//! advertises `encryption != OFF`) the TLS-in-TDS handshake via
//! [`crate::tls::upgrade_to_tls`]. `login_ntlm` performs the full NTLM Type 1 /
//! Type 3 exchange over the (possibly encrypted) transport. `sql_batch` sends
//! the batch and drains the response — messages, errors, and the DONE row_count
//! come back — but ROW / COLMETADATA decoding is future work, so
//! `ResultSet.rows` / `ResultSet.columns` stay empty.

use ntlmssp::Ntlm;
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::login7::Login7;
use crate::packet::PacketType;
use crate::prelogin::{encryption, PreLogin};
use crate::token::{parse_all, Token};
use crate::transport::{AsyncStream, Transport};

/// One column in a result set.
#[derive(Debug, Clone)]
pub struct Column {
    pub name: String,
    pub type_id: u8,
}

/// One decoded row. Values are stored as strings for now — a typed variant
/// enum is future work once ROW decoding lands.
#[derive(Debug, Clone, Default)]
pub struct Row {
    pub values: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct ResultSet {
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
    /// Informational messages (PRINT, RAISERROR severity < 11, etc).
    pub messages: Vec<String>,
    /// `row_count` from the terminating DONE token.
    pub row_count: u64,
}

impl ResultSet {
    pub fn empty() -> Self {
        Self::default()
    }
}

pub struct TdsClient {
    transport: Transport,
    server: String,
    logged_in: bool,
    encrypted: bool,
}

impl TdsClient {
    /// Open a TCP connection and perform the PreLogin (+ optional TLS-in-TDS)
    /// handshake.
    ///
    /// `instance` is accepted for API-shape compatibility but is not used yet —
    /// named-instance resolution needs the SQL Browser (UDP 1434) which is not
    /// implemented here.
    pub async fn connect(host: &str, port: u16, _instance: Option<&str>) -> Result<Self> {
        let stream = TcpStream::connect((host, port)).await?;
        Self::from_stream(Box::new(stream), host.to_string()).await
    }

    /// Drive PreLogin + optional TLS upgrade over an arbitrary caller-supplied
    /// stream. This is the testing seam — pair it with `tokio::io::duplex` to
    /// exercise the handshake without needing a real SQL Server socket.
    pub async fn from_stream(stream: Box<dyn AsyncStream>, server: String) -> Result<Self> {
        let mut transport = Transport::new_boxed(stream);

        // Advertise "encryption OFF" — we don't require it but will honor the
        // server's demand. Real SQL Server 2019+ ships `Force Encryption = yes`
        // by default, so the server will respond with ENCRYPT_REQ.
        let mut pre = PreLogin::new_default();
        pre.encryption = encryption::OFF;
        transport.send(PacketType::PreLogin, &pre.encode()).await?;

        let (kind, body) = transport.recv().await?;
        if kind != PacketType::TabularResult && kind != PacketType::PreLogin {
            return Err(Error::Protocol("prelogin: unexpected response type"));
        }
        let server_pre = PreLogin::decode(&body)?;

        // Honor server's ENCRYPTION advertisement.
        //
        // OFF / NOT_SUP: server does not want / cannot do TLS — continue plaintext.
        // ON:            server wants login encrypted only. We treat it as REQ
        //                (encrypt the whole session) — that's what every modern
        //                TDS client does, and modern SQL Server accepts it.
        // REQ:           server demands full-session encryption — upgrade now.
        let encrypted = match server_pre.encryption {
            encryption::REQ | encryption::ON => {
                let cfg = crate::tls::client_config_trust_any();
                transport = crate::tls::upgrade_to_tls(transport, &server, cfg).await?;
                true
            }
            encryption::OFF | encryption::NOT_SUP => false,
            _ => return Err(Error::Protocol("prelogin: unknown ENCRYPTION value")),
        };

        Ok(Self {
            transport,
            server,
            logged_in: false,
            encrypted,
        })
    }

    /// True if the session is running over TLS (server advertised
    /// ENCRYPT_ON / ENCRYPT_REQ at PreLogin and the handshake completed).
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// NTLM (SSPI) authentication.
    ///
    /// Sends Login7 with an NTLMSSP NEGOTIATE (Type 1) blob embedded in the
    /// ibSSPI slot. The server replies with an SSPI token wrapping the
    /// CHALLENGE (Type 2); the client answers with AUTHENTICATE (Type 3) in an
    /// SSPI-type packet. Success is signalled by a LOGINACK token.
    ///
    /// TODO: Kerberos via SPNEGO is not wired up. Channel binding / extended
    /// protection for TLS-in-TDS also outstanding.
    pub async fn login_ntlm(&mut self, domain: &str, user: &str, password: &str) -> Result<()> {
        let ntlm = Ntlm::new();
        let type1 = ntlm.negotiate().to_vec();
        let host = hostname_fallback();
        let login = Login7::new_sspi(&host, &self.server, "", type1);
        self.transport
            .send(PacketType::Login7, &login.encode())
            .await?;

        loop {
            let (_kind, body) = self.transport.recv().await?;
            let tokens = parse_all(&body)?;
            let mut sent_type3 = false;
            for tok in tokens {
                match tok {
                    Token::Sspi(challenge) => {
                        let (type3, _key) =
                            ntlm.authenticate(&challenge, domain, user, password, &host)?;
                        self.transport.send(PacketType::Sspi, &type3).await?;
                        sent_type3 = true;
                    }
                    Token::LoginAck { .. } => {
                        self.logged_in = true;
                        return Ok(());
                    }
                    Token::Error {
                        number, message, ..
                    } => {
                        return Err(Error::Server {
                            code: number,
                            message,
                        });
                    }
                    _ => {}
                }
            }
            if !sent_type3 {
                // No SSPI challenge and no LOGINACK — server closed us out silently
                // or returned only ENVCHANGE / DONE. Bail rather than loop forever.
                return Err(Error::Protocol(
                    "login: no SSPI challenge or LOGINACK in response",
                ));
            }
        }
    }

    /// Send a SQL batch. Returns the DONE row_count plus any INFO/PRINT
    /// messages — column values are NOT decoded yet (see module docs).
    pub async fn sql_batch(&mut self, query: &str) -> Result<ResultSet> {
        // ALL_HEADERS (MS-TDS 2.2.5.3): every batch/RPC carries a small header
        // block. The transaction-descriptor header (type 0x0002) is mandatory
        // outside MARS: a zero descriptor + outstanding-request-count 1 is legal.
        let mut payload = Vec::with_capacity(22 + query.len() * 2);
        let mut td = Vec::with_capacity(18);
        td.extend_from_slice(&18u32.to_le_bytes()); // this-header length (incl. self)
        td.extend_from_slice(&2u16.to_le_bytes()); // header type: transaction descriptor
        td.extend_from_slice(&0u64.to_le_bytes()); // TransactionDescriptor
        td.extend_from_slice(&1u32.to_le_bytes()); // OutstandingRequestCount
        let total_all_headers = (4 + td.len()) as u32;
        payload.extend_from_slice(&total_all_headers.to_le_bytes());
        payload.extend_from_slice(&td);
        for u in query.encode_utf16() {
            payload.extend_from_slice(&u.to_le_bytes());
        }

        self.transport.send(PacketType::SqlBatch, &payload).await?;
        let (_, body) = self.transport.recv().await?;
        let mut rs = ResultSet::empty();

        // Best-effort parse. If the stream carries ROW/COLMETADATA (which we
        // can't yet decode) we still surface any messages / errors / DONE that
        // came before the failure — parse_all returns Unsupported on those.
        let tokens = match parse_all(&body) {
            Ok(t) => t,
            Err(Error::Unsupported(_)) => Vec::new(),
            Err(e) => return Err(e),
        };
        for tok in tokens {
            match tok {
                Token::Error {
                    number, message, ..
                } => {
                    return Err(Error::Server {
                        code: number,
                        message,
                    });
                }
                Token::Info { message, .. } => rs.messages.push(message),
                Token::Done { row_count, .. } => rs.row_count = row_count,
                _ => {}
            }
        }
        Ok(rs)
    }

    pub fn is_logged_in(&self) -> bool {
        self.logged_in
    }
}

fn hostname_fallback() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "ms-tds-client".to_string())
}
