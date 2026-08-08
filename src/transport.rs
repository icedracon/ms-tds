//! Async transport with TDS packet framing.
//!
//! The transport holds a `Box<dyn AsyncStream>` — plain TCP for pre-TLS traffic,
//! or the `TlsStream<TlsTunnel<...>>` produced by [`crate::tls::upgrade_to_tls`]
//! after the TLS-in-TDS handshake completes. TDS packet framing sits on top of
//! that stream unchanged: post-TLS, the TLS layer transparently encrypts the
//! bytes we write and decrypts the bytes we read.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::packet::{status, Header, PacketType, DEFAULT_PACKET_SIZE, HEADER_LEN};
use crate::Result;

/// Trait alias for the shape the transport can drive: async, bidirectional,
/// `Send + Unpin`. Blanket-implemented for anything satisfying those bounds so
/// callers rarely name it directly — `TcpStream`, `DuplexStream`, and
/// `TlsStream<..>` all qualify automatically.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> AsyncStream for T {}

pub struct Transport {
    stream: Box<dyn AsyncStream>,
    packet_size: u16,
    next_pkt_id: u8,
}

impl Transport {
    /// Convenience wrapper — box a `TcpStream` and hand it to the transport.
    pub fn new(stream: TcpStream) -> Self {
        Self::new_boxed(Box::new(stream))
    }

    /// Wrap an already-boxed async stream. Used both for the plaintext TCP
    /// path and for the post-TLS-upgrade `TlsStream<TlsTunnel<_>>`.
    pub fn new_boxed(stream: Box<dyn AsyncStream>) -> Self {
        Self {
            stream,
            packet_size: DEFAULT_PACKET_SIZE,
            next_pkt_id: 1,
        }
    }

    /// Consume the transport and hand back the underlying stream — the seam
    /// used to upgrade a live plaintext connection to TLS-in-TDS.
    pub fn into_stream(self) -> Box<dyn AsyncStream> {
        self.stream
    }

    /// Update the negotiated packet size (server advertises via ENV_CHANGE type 4).
    /// Values below 512 are clamped up to 512 — SQL Server rejects anything smaller.
    pub fn set_packet_size(&mut self, sz: u16) {
        self.packet_size = sz.max(512);
    }

    pub fn packet_size(&self) -> u16 {
        self.packet_size
    }

    /// Send `payload` as one TDS message, framed into 1+ packets.
    pub async fn send(&mut self, ptype: PacketType, payload: &[u8]) -> Result<()> {
        let max_body = (self.packet_size as usize)
            .saturating_sub(HEADER_LEN)
            .max(1);
        let mut id = self.next_pkt_id;
        let chunks: Vec<&[u8]> = if payload.is_empty() {
            vec![&[]]
        } else {
            payload.chunks(max_body).collect()
        };
        let last = chunks.len() - 1;
        for (i, chunk) in chunks.iter().enumerate() {
            let stat = if i == last {
                status::END_OF_MESSAGE
            } else {
                status::NORMAL
            };
            let mut hdr_buf = [0u8; HEADER_LEN];
            let hdr = Header::new(ptype, stat, (HEADER_LEN + chunk.len()) as u16, id);
            hdr.encode(&mut hdr_buf);
            self.stream.write_all(&hdr_buf).await?;
            if !chunk.is_empty() {
                self.stream.write_all(chunk).await?;
            }
            id = id.wrapping_add(1);
        }
        self.stream.flush().await?;
        self.next_pkt_id = id;
        Ok(())
    }

    /// Read one complete TDS message — concatenates packet payloads until a
    /// packet arrives with `END_OF_MESSAGE` set. Returns the type of the first
    /// packet and the joined body.
    pub async fn recv(&mut self) -> Result<(PacketType, Vec<u8>)> {
        let mut ptype: Option<PacketType> = None;
        let mut body = Vec::new();
        loop {
            let mut hdr_buf = [0u8; HEADER_LEN];
            self.stream.read_exact(&mut hdr_buf).await?;
            let hdr = Header::decode(&hdr_buf)?;
            ptype.get_or_insert(hdr.ptype);
            let body_len = (hdr.length as usize).saturating_sub(HEADER_LEN);
            if body_len > 0 {
                let mut chunk = vec![0u8; body_len];
                self.stream.read_exact(&mut chunk).await?;
                body.extend_from_slice(&chunk);
            }
            if (hdr.status & status::END_OF_MESSAGE) != 0 {
                break;
            }
        }
        Ok((ptype.expect("at least one packet was read"), body))
    }
}
