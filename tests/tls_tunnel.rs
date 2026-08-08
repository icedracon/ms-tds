//! Tests for the TLS-in-TDS handshake tunneling wrapper.
//!
//! Three levels of coverage:
//!
//! 1. `tls_tunnel_wraps_write_in_prelogin_packet` — a single write on the tunnel
//!    reaches the far end as one TDS PRELOGIN packet with correct header + body.
//! 2. `tls_tunnel_unwraps_prelogin_packet_on_read` — the tunnel strips PRELOGIN
//!    framing from inbound bytes and delivers the body as a plain byte stream.
//! 3. `tls_handshake_completes_over_tunnel` — full end-to-end TLS 1.2/1.3
//!    handshake using real rustls state machines on BOTH sides, each wrapping
//!    its stream in a `TlsTunnel`. Proves the tunneling primitive is compatible
//!    with a live TLS peer, which is the load-bearing scenario for MS-TDS
//!    §3.3.5.1.
//! 4. `tds_client_from_stream_completes_prelogin_and_tls` — drives the actual
//!    `TdsClient::from_stream` code path through PreLogin + TLS handshake
//!    against a mock TDS server.

use std::sync::Arc;

use ms_tds::packet::{status, Header, PacketType, HEADER_LEN};
use ms_tds::prelogin::{encryption, PreLogin};
use ms_tds::tls::client_config_trust_any;
use ms_tds::tls_tunnel::{TlsTunnel, TunnelMode};
use ms_tds::transport::Transport;
use ms_tds::TdsClient;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ---------------------------------------------------------------------------
// (1) Write wrapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_tunnel_wraps_write_in_prelogin_packet() {
    let (client, mut server) = tokio::io::duplex(4096);
    let mode = TunnelMode::new_handshake();
    let mut tunnel = TlsTunnel::new(client, mode);

    let payload = b"CLIENT-HELLO-BYTES-GO-HERE";
    tunnel.write_all(payload).await.unwrap();
    tunnel.flush().await.unwrap();

    // The far side should see: 8-byte TDS PRELOGIN header + payload.
    let mut hdr = [0u8; HEADER_LEN];
    server.read_exact(&mut hdr).await.unwrap();
    let decoded = Header::decode(&hdr).unwrap();
    assert_eq!(decoded.ptype, PacketType::PreLogin);
    assert_eq!(
        decoded.status & status::END_OF_MESSAGE,
        status::END_OF_MESSAGE,
        "PRELOGIN wrap must set END_OF_MESSAGE"
    );
    assert_eq!(decoded.length as usize, HEADER_LEN + payload.len());

    let mut body = vec![0u8; payload.len()];
    server.read_exact(&mut body).await.unwrap();
    assert_eq!(body, payload);
}

// ---------------------------------------------------------------------------
// (2) Read unwrapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_tunnel_unwraps_prelogin_packet_on_read() {
    let (client, mut server) = tokio::io::duplex(4096);
    let mode = TunnelMode::new_handshake();
    let mut tunnel = TlsTunnel::new(client, mode);

    let payload = b"SERVER-HELLO-BYTES";
    let mut pkt = Vec::new();
    let mut hbuf = [0u8; HEADER_LEN];
    Header::new(
        PacketType::PreLogin,
        status::END_OF_MESSAGE,
        (HEADER_LEN + payload.len()) as u16,
        1,
    )
    .encode(&mut hbuf);
    pkt.extend_from_slice(&hbuf);
    pkt.extend_from_slice(payload);
    server.write_all(&pkt).await.unwrap();
    server.flush().await.unwrap();

    let mut got = vec![0u8; payload.len()];
    tunnel.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);
}

// ---------------------------------------------------------------------------
// (3) End-to-end TLS handshake through paired tunnels
// ---------------------------------------------------------------------------

fn build_server_config() -> Arc<ServerConfig> {
    let ca =
        rcgen::generate_simple_self_signed(vec!["testserver".to_string()]).expect("rcgen cert");
    let cert_der: CertificateDer<'static> = ca.cert.der().clone();
    let key_bytes = ca.key_pair.serialize_der();
    let key_der: PrivateKeyDer<'static> = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));

    let provider = tokio_rustls::rustls::crypto::ring::default_provider();
    let cfg = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("safe default TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("valid cert/key");
    Arc::new(cfg)
}

#[tokio::test]
async fn tls_handshake_completes_over_tunnel() {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);

    let client_mode = TunnelMode::new_handshake();
    let server_mode = TunnelMode::new_handshake();

    let client_tunnel = TlsTunnel::new(client_side, client_mode.clone());
    let server_tunnel = TlsTunnel::new(server_side, server_mode.clone());

    let connector = TlsConnector::from(client_config_trust_any());
    let acceptor = TlsAcceptor::from(build_server_config());

    let sn: ServerName<'static> = ServerName::try_from("testserver".to_string()).unwrap();

    let client_fut = async {
        let s = connector.connect(sn, client_tunnel).await?;
        client_mode.set_passthrough();
        Ok::<_, std::io::Error>(s)
    };
    let server_fut = async {
        let s = acceptor.accept(server_tunnel).await?;
        server_mode.set_passthrough();
        Ok::<_, std::io::Error>(s)
    };

    let (client_res, server_res) = tokio::join!(client_fut, server_fut);
    let mut client_tls = client_res.expect("client handshake");
    let mut server_tls = server_res.expect("server handshake");

    // Round-trip application data through the now-encrypted, passthrough
    // channel to prove the handshake produced a working session key.
    let msg = b"ENCRYPTED-APP-DATA";
    client_tls.write_all(msg).await.unwrap();
    client_tls.flush().await.unwrap();
    let mut got = vec![0u8; msg.len()];
    server_tls.read_exact(&mut got).await.unwrap();
    assert_eq!(got, msg);

    let reply = b"PONG";
    server_tls.write_all(reply).await.unwrap();
    server_tls.flush().await.unwrap();
    let mut got2 = vec![0u8; reply.len()];
    client_tls.read_exact(&mut got2).await.unwrap();
    assert_eq!(got2, reply);
}

// ---------------------------------------------------------------------------
// (4) TdsClient::from_stream drives PreLogin + TLS upgrade end-to-end
// ---------------------------------------------------------------------------

/// Mock TDS server: reads client's PreLogin, replies with ENCRYPT_REQ, then
/// completes the TLS-in-TDS handshake using a real rustls Acceptor sitting on
/// top of the tunnel.
async fn mock_tds_server(stream: tokio::io::DuplexStream) -> std::io::Result<()> {
    let mut transport = Transport::new_boxed(Box::new(stream));

    // (a) Receive client's PreLogin.
    let (kind, body) = transport
        .recv()
        .await
        .map_err(|e| std::io::Error::other(format!("mock recv: {e}")))?;
    assert_eq!(kind, PacketType::PreLogin);
    let _client_pre = PreLogin::decode(&body).expect("client sent valid PreLogin");

    // (b) Send server PreLogin with encryption REQUIRED.
    let mut server_pre = PreLogin::new_default();
    server_pre.encryption = encryption::REQ;
    transport
        .send(PacketType::PreLogin, &server_pre.encode())
        .await
        .map_err(|e| std::io::Error::other(format!("mock send: {e}")))?;

    // (c) Extract the raw stream and drive the TLS handshake through a
    //     server-side tunnel + rustls Acceptor.
    let raw = transport.into_stream();
    let mode = TunnelMode::new_handshake();
    let tunnel = TlsTunnel::new(raw, mode.clone());
    let acceptor = TlsAcceptor::from(build_server_config());
    let _tls = acceptor.accept(tunnel).await?;
    mode.set_passthrough();
    Ok(())
}

#[tokio::test]
async fn tds_client_from_stream_completes_prelogin_and_tls() {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let server_join = tokio::spawn(mock_tds_server(server_side));
    let client = TdsClient::from_stream(Box::new(client_side), "testserver".to_string())
        .await
        .expect("client from_stream should complete PreLogin + TLS");
    assert!(client.is_encrypted(), "post-PreLogin must be encrypted");
    server_join.await.expect("mock task").expect("mock ok");
}
