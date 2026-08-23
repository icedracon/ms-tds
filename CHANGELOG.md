# Changelog

## 0.1.1 — WS-1 primitives (unpublished, adhammer 1.4.1 dev)

- `TdsClient::run_query` — bulk-collect wrapper around `sql_batch` (semantic
  distinction; today identical shape, gated on the ROW decoder for real row
  values).
- `TdsClient::impersonate(principal)` — issues `EXECUTE AS LOGIN = '<principal>'`
  (server scope). Stacks on repeated calls.
- `TdsClient::revert_to_self` — issues `REVERT` (pops one impersonation frame).
- `pentest::execute_as_login` / `pentest::execute_as_user` / `pentest::revert` —
  SQL string builders for the impersonation primitives, with single-quote
  escaping in principal names.

Consumed via `[patch.crates-io]` by adhammer's `attack mssql` (WS-1) in dev.
Not published — see 1.4.1 stay-local directive.

## 0.1.0 — initial

- TDS packet framing + PreLogin
- TLS-in-TDS handshake tunneling (rustls, ring backend)
- Login7 with NTLM SSPI (INTEGRATED_SECURITY)
- `sql_batch` — sends the batch, drains INFO/ERROR/DONE (ROW decoding TODO)
- `pentest` module — `xp_cmdshell`, `xp_dirtree` UNC coerce, linked-server
  enumeration, `sp_configure` toggle, `IS_SRVROLEMEMBER` probe
