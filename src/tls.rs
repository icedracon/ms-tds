//! TLS-in-TDS handshake driver.
//!
//! Ties [`crate::tls_tunnel::TlsTunnel`] together with `tokio-rustls`: builds a
//! `ClientConfig` (with a permissive verifier by default — see [`NoCertVerify`]),
//! wraps the plaintext stream in a tunnel in handshake mode, drives the
//! `TlsConnector` to completion, then flips the tunnel to passthrough. The
//! returned [`crate::transport::Transport`] wraps the TLS stream so TDS packet
//! framing continues to work — writes are transparently encrypted, reads
//! transparently decrypted.

use std::sync::Arc;

use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::error::{Error, Result};
use crate::tls_tunnel::{TlsTunnel, TunnelMode};
use crate::transport::Transport;

/// A trust-anything server-cert verifier.
///
/// SQL Server deployments almost universally use self-signed certs auto-
/// generated at first boot; production trust anchoring lives outside PKI
/// (server SPN + Kerberos / integrated auth). This verifier mirrors what
/// `sqlcmd -N -C` ("encrypt yes, trust server cert") gives you. Do NOT
/// reuse for general HTTPS.
#[derive(Debug)]
pub struct NoCertVerify;

impl ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Build a rustls `ClientConfig` bound to the [`NoCertVerify`] verifier,
/// using the pure-Rust `ring` crypto provider (the crate refuses to bring in
/// `aws-lc-rs` / cmake / nasm on Windows).
pub fn client_config_trust_any() -> Arc<rustls::ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("safe default TLS versions available")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerify))
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Consume a plaintext [`Transport`], run the TLS-in-TDS handshake, and
/// return a new [`Transport`] backed by the TLS-wrapped stream.
///
/// The `server_name` is what rustls signs into the SNI extension — it should
/// match the hostname the caller used to open the socket (any DNS name works;
/// with the default [`NoCertVerify`] verifier it isn't cross-checked).
///
/// # Post-condition
/// On success the tunnel has been flipped to passthrough mode: from this point
/// on the underlying byte stream carries raw TLS records directly on TCP, as
/// MS-TDS §3.3.5.1 mandates. TDS packet framing sits on top of the TLS layer
/// unchanged — subsequent [`Transport::send`] / [`Transport::recv`] calls
/// transparently produce/consume encrypted TDS.
pub async fn upgrade_to_tls(
    transport: Transport,
    server_name: &str,
    config: Arc<rustls::ClientConfig>,
) -> Result<Transport> {
    let inner = transport.into_stream();
    let mode = TunnelMode::new_handshake();
    let tunnel = TlsTunnel::new(inner, mode.clone());
    let connector = TlsConnector::from(config);
    let sn: ServerName<'static> = ServerName::try_from(server_name.to_string())
        .map_err(|_| Error::Protocol("tls: invalid server name for SNI"))?;
    let tls = connector
        .connect(sn, tunnel)
        .await
        .map_err(|e| Error::Tls(e.to_string()))?;
    // Handshake complete — from now on the stream carries raw TLS records
    // directly on TCP (MS-TDS §3.3.5.1). Flip the tunnel out of the wrapping
    // path BEFORE any further byte movement.
    mode.set_passthrough();
    Ok(Transport::new_boxed(Box::new(tls)))
}
