//! TLS-in-TDS handshake tunneling wrapper (MS-TDS §3.3.5.1).
//!
//! TDS is unique among wire protocols in that its TLS handshake runs INSIDE
//! TDS PRELOGIN (0x12) packets: the ClientHello, ServerHello, certificate,
//! and all remaining handshake records are each wrapped in a TDS packet
//! header before hitting the TCP socket. Once the handshake completes the
//! spec says raw TLS records flow directly on TCP (no more TDS wrapping) —
//! so this wrapper transitions between those two framings on each side of
//! the connection.
//!
//! ## Framing directions are asymmetric
//!
//! * **Write side** uses an explicit [`TunnelMode`]. While it says
//!   "handshake", every outbound byte-chunk is wrapped in one PRELOGIN
//!   packet; once the driver flips it to "passthrough" (right after
//!   `TlsConnector::connect` returns `Ok`), writes bypass the wrapper.
//!
//! * **Read side is auto-detecting**. Peers on both ends of the tunnel flip
//!   modes independently, so bytes arriving from the far side may already
//!   be raw TLS records even though our own write side is still wrapping,
//!   or vice-versa. Fortunately the two framings are unambiguous: TDS
//!   PRELOGIN starts with `0x12`, TLS records with `0x14`/`0x15`/`0x16`/`0x17`
//!   — completely disjoint. So on read we peek the first byte of each
//!   new packet: `0x12` → unwrap PRELOGIN; anything else → passthrough
//!   the byte plus whatever else the inner stream will hand us.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::packet::{status, Header, PacketType, HEADER_LEN};

/// Shared handshake/passthrough switch on the WRITE side. Clone one handle
/// into the tunnel and keep the other next to the connector — the driver
/// flips it to passthrough the moment the TLS handshake completes so that
/// application-data writes are no longer PRELOGIN-wrapped.
#[derive(Debug, Clone, Default)]
pub struct TunnelMode(Arc<AtomicBool>);

impl TunnelMode {
    /// Start in handshake mode: outbound writes are wrapped in PRELOGIN.
    pub fn new_handshake() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    /// Flip the write side to passthrough. Reads remain auto-detecting.
    pub fn set_passthrough(&self) {
        self.0.store(false, Ordering::SeqCst);
    }

    #[inline]
    fn is_handshake(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Read-side state machine: what are we in the middle of doing on the inner
/// stream right now?
#[derive(Debug)]
enum ReadPhase {
    /// No packet in progress. Peek one byte from the inner stream to decide
    /// PRELOGIN-framed or raw-passthrough.
    Idle,
    /// First byte was `0x12` — filling the rest of the 8-byte TDS header.
    /// `r_hdr[0]` already holds the peeked byte; `hdr_fill` counts bytes
    /// present (starts at 1).
    Header { hdr_fill: usize },
    /// Header parsed; reading `body_len` body bytes into `r_body`.
    Body { body_fill: usize, body_len: usize },
    /// Body ready; delivering `body_len` bytes from `r_body` to the caller.
    Deliver { body_pos: usize, body_len: usize },
    /// First peeked byte was NOT `0x12` — treat this "packet" as raw TLS.
    /// Deliver the peeked byte, then delegate straight to the inner stream
    /// until we hand back a Ready that lands us back in `Idle`.
    Raw { peeked: Option<u8> },
}

/// PRELOGIN-tunneling wrapper. See module docs.
pub struct TlsTunnel<S> {
    inner: S,
    mode: TunnelMode,
    // Read side
    r_hdr: [u8; HEADER_LEN],
    r_body: Vec<u8>,
    r_phase: ReadPhase,
    // Write side
    w_buf: Vec<u8>,
    w_pos: usize,
    packet_id: u8,
}

impl<S> TlsTunnel<S> {
    pub fn new(inner: S, mode: TunnelMode) -> Self {
        Self {
            inner,
            mode,
            r_hdr: [0u8; HEADER_LEN],
            r_body: Vec::new(),
            r_phase: ReadPhase::Idle,
            w_buf: Vec::new(),
            w_pos: 0,
            packet_id: 1,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsTunnel<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.r_phase {
                ReadPhase::Idle => {
                    // Peek one byte to decide framing.
                    let mut one = [0u8; 1];
                    let mut peek = ReadBuf::new(&mut one);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut peek) {
                        Poll::Ready(Ok(())) => {
                            let n = peek.filled().len();
                            if n == 0 {
                                // Clean EOF.
                                return Poll::Ready(Ok(()));
                            }
                            if one[0] == PacketType::PreLogin as u8 {
                                this.r_hdr[0] = one[0];
                                this.r_phase = ReadPhase::Header { hdr_fill: 1 };
                            } else {
                                this.r_phase = ReadPhase::Raw {
                                    peeked: Some(one[0]),
                                };
                            }
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                ReadPhase::Header { hdr_fill } => {
                    if hdr_fill < HEADER_LEN {
                        let mut hbuf = ReadBuf::new(&mut this.r_hdr[hdr_fill..HEADER_LEN]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut hbuf) {
                            Poll::Ready(Ok(())) => {
                                let n = hbuf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::from(
                                        io::ErrorKind::UnexpectedEof,
                                    )));
                                }
                                this.r_phase = ReadPhase::Header {
                                    hdr_fill: hdr_fill + n,
                                };
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    } else {
                        // Header complete — decode and transition.
                        let hdr = Header::decode(&this.r_hdr).map_err(io::Error::other)?;
                        if hdr.ptype != PacketType::PreLogin {
                            // Peek said 0x12 but this shouldn't happen. Guard anyway.
                            return Poll::Ready(Err(io::Error::other(
                                "tls-tunnel: framed header had non-PRELOGIN packet type",
                            )));
                        }
                        let body_len = (hdr.length as usize).saturating_sub(HEADER_LEN);
                        if body_len == 0 {
                            // Empty body — back to Idle.
                            this.r_phase = ReadPhase::Idle;
                        } else {
                            if this.r_body.len() < body_len {
                                this.r_body.resize(body_len, 0);
                            }
                            this.r_phase = ReadPhase::Body {
                                body_fill: 0,
                                body_len,
                            };
                        }
                    }
                }

                ReadPhase::Body {
                    body_fill,
                    body_len,
                } => {
                    if body_fill < body_len {
                        let mut bbuf = ReadBuf::new(&mut this.r_body[body_fill..body_len]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut bbuf) {
                            Poll::Ready(Ok(())) => {
                                let n = bbuf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::from(
                                        io::ErrorKind::UnexpectedEof,
                                    )));
                                }
                                this.r_phase = ReadPhase::Body {
                                    body_fill: body_fill + n,
                                    body_len,
                                };
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    } else {
                        this.r_phase = ReadPhase::Deliver {
                            body_pos: 0,
                            body_len,
                        };
                    }
                }

                ReadPhase::Deliver { body_pos, body_len } => {
                    let n = (body_len - body_pos).min(buf.remaining());
                    if n == 0 {
                        // Caller has no room and no bytes were delivered —
                        // signal readiness with an empty fill.
                        return Poll::Ready(Ok(()));
                    }
                    buf.put_slice(&this.r_body[body_pos..body_pos + n]);
                    let new_pos = body_pos + n;
                    if new_pos == body_len {
                        this.r_phase = ReadPhase::Idle;
                    } else {
                        this.r_phase = ReadPhase::Deliver {
                            body_pos: new_pos,
                            body_len,
                        };
                    }
                    return Poll::Ready(Ok(()));
                }

                ReadPhase::Raw { peeked } => {
                    // Deliver the peeked byte first, then whatever the inner
                    // stream gives us in a single read — that's classic
                    // passthrough behavior.
                    if let Some(b) = peeked {
                        if buf.remaining() == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        buf.put_slice(&[b]);
                        // Keep the peeked slot cleared, and try to fill more.
                        this.r_phase = ReadPhase::Raw { peeked: None };
                    }
                    match Pin::new(&mut this.inner).poll_read(cx, buf) {
                        Poll::Ready(Ok(())) => {
                            // Return to Idle: the next call will peek the first
                            // byte of the next chunk (which may be either
                            // framing — auto-detected again).
                            this.r_phase = ReadPhase::Idle;
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            // Even in Pending, if we already delivered the
                            // peeked byte, tokio's contract lets us return
                            // Ready. Fall back to Pending only if nothing
                            // was delivered — but we already put the byte,
                            // so return Ready with whatever's in buf.
                            if !buf.filled().is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Pending;
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsTunnel<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.mode.is_handshake() {
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }

        // Drain any previously-buffered packet first.
        while this.w_pos < this.w_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.w_buf[this.w_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => this.w_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Frame the caller's bytes into one TDS PRELOGIN packet. The 16-bit
        // length field caps the body at 65535 - 8 bytes; longer writes need
        // multiple packets, so cap at MAX_BODY and report chunk_len to the
        // caller (rustls will resume with the remainder on the next call).
        const MAX_BODY: usize = u16::MAX as usize - HEADER_LEN;
        let chunk_len = data.len().min(MAX_BODY);
        let mut hbuf = [0u8; HEADER_LEN];
        let hdr = Header::new(
            PacketType::PreLogin,
            status::END_OF_MESSAGE,
            (HEADER_LEN + chunk_len) as u16,
            this.packet_id,
        );
        hdr.encode(&mut hbuf);
        this.packet_id = this.packet_id.wrapping_add(1);

        this.w_buf.clear();
        this.w_buf.reserve(HEADER_LEN + chunk_len);
        this.w_buf.extend_from_slice(&hbuf);
        this.w_buf.extend_from_slice(&data[..chunk_len]);
        this.w_pos = 0;

        // Try to write it immediately.
        while this.w_pos < this.w_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.w_buf[this.w_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => this.w_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // Caller's data is safely buffered — the remaining framed
                    // bytes will be drained on the next poll_write/flush.
                    return Poll::Ready(Ok(chunk_len));
                }
            }
        }

        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.w_pos < this.w_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.w_buf[this.w_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => this.w_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.w_pos < this.w_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.w_buf[this.w_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => this.w_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
