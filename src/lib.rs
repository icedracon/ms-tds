//! `ms-tds` — pure-Rust TDS 7.4 client for Microsoft SQL Server.
//!
//! # STATUS: pre-alpha
//!
//! Compile-clean skeleton with partial implementation:
//!
//! * TDS packet framing (header + segmentation across `packet_size`)
//! * PreLogin token round-trip
//! * Login7 with NTLM SSPI blob wrapping (INTEGRATED_SECURITY)
//! * `TdsClient` `connect` / `login_ntlm` / `sql_batch` — the wire is driven
//!   but ROW / COLMETADATA decoding is not implemented, so `sql_batch` returns
//!   an empty `ResultSet` even when the server sends rows.
//! * TLS-in-TDS: not implemented (server must accept unencrypted login).
//!
//! # Minimal usage sketch
//!
//! ```no_run
//! # async fn f() -> ms_tds::Result<()> {
//! let mut c = ms_tds::TdsClient::connect("sql01", 1433, None).await?;
//! c.login_ntlm("CORP", "svc_scan", "pw").await?;
//! let _ = c.sql_batch(ms_tds::pentest::enum_linked_servers()).await?;
//! # Ok(()) }
//! ```

#![deny(unsafe_code)]

pub mod client;
pub mod error;
pub mod login7;
pub mod packet;
pub mod pentest;
pub mod prelogin;
pub mod token;
pub mod transport;

pub use client::{Column, ResultSet, Row, TdsClient};
pub use error::{Error, Result};
