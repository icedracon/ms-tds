use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ntlm: {0}")]
    Ntlm(#[from] ntlmssp::NtlmError),
    #[error("protocol: {0}")]
    Protocol(&'static str),
    #[error("short read: expected {expected}, got {got}")]
    ShortRead { expected: usize, got: usize },
    #[error("invalid packet type: {0:#x}")]
    InvalidPacketType(u8),
    #[error("server error {code}: {message}")]
    Server { code: u32, message: String },
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
