# ms-tds

Pure-Rust TDS 7.4 client for Microsoft SQL Server, with an offensive-security
lean (pentest primitives shipped in-tree).

## STATUS: pre-alpha (0.1.0-dev)

Compile-clean skeleton with a partial implementation. Not fit for anything
beyond exploration.

### What works

- TDS packet framing — 8-byte BE header, `frame()` segments a payload across
  `packet_size`, `Transport::recv()` reassembles until `END_OF_MESSAGE`.
- PreLogin encode / decode round-trips.
- Login7 encode — full fixed header + OffsetLength block + variable data,
  including NTLM SSPI blob in the ibSSPI slot with `INTEGRATED_SECURITY` flag.
- Login7 password obfuscation (`XOR 0xA5` + nibble-swap).
- Token stream reader for: LOGINACK, SSPI, ENVCHANGE, DONE / DONEPROC /
  DONEINPROC, INFO, ERROR.
- Async `TdsClient` with `connect` / `login_ntlm` / `sql_batch` — the wire
  handshakes are driven end-to-end.
- Pentest string builders: `xp_cmdshell`, `xp_dirtree` UNC coerce, linked-server
  enumeration, `IS_SRVROLEMEMBER`, `sp_configure` toggle.

### What is stubbed / TODO

- **TLS-in-TDS**: not implemented. Server must accept unencrypted login (i.e.
  legacy setup or `Encrypt=false`). Modern SQL Server defaults will refuse.
- **ROW / COLMETADATA decoding**: `sql_batch` returns an empty `ResultSet`
  even when the server sends rows. Row decoding needs the full TYPE_INFO
  matrix (variable-length prefixes, COLLATION for VARCHAR, precision/scale for
  NUMERIC, PLP for `varchar(max)`/`text`/`image`).
- **SQL Browser (UDP 1434)**: named-instance resolution is not implemented —
  `connect()` accepts `instance: Option<&str>` for API-shape stability but
  ignores it.
- **Kerberos SPNEGO**: `login_ntlm` is NTLM-only.
- **Channel binding / Extended Protection**: outstanding.

### Minimal usage

```rust,no_run
use ms_tds::{TdsClient, pentest};

# async fn f() -> ms_tds::Result<()> {
let mut c = TdsClient::connect("sql01", 1433, None).await?;
c.login_ntlm("CORP", "svc_scan", "hunter2").await?;
let rs = c.sql_batch(pentest::enum_linked_servers()).await?;
println!("done, row_count = {}", rs.row_count);
# Ok(()) }
```

### Design

- One thin module per protocol layer:
  `packet` → `prelogin` / `login7` / `token` → `transport` → `client`.
- No unsafe.
- Dependency budget kept small: `ntlmssp` (SSPI blobs), `thiserror`, `tokio`,
  `tokio-rustls` (ring-backend, reserved for future TLS-in-TDS), plus
  `byteorder` / `bytes` / `encoding_rs` staged for the ROW decoder.

### License

MIT.
