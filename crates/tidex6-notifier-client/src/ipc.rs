//! Length-prefixed bitcode framing over a Unix socket.
//!
//! Mirrors the `tidex6-web::utils::ipc` helper one-for-one — moved
//! here so consumers outside the web crate (the relayer, future
//! microservices) can depend on the protocol without pulling in the
//! whole web service. The web crate itself re-uses these helpers via
//! a thin wrapper to keep its own call sites unchanged.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Largest legal payload (100 MB). Anything bigger is treated as a
/// framing error and the read returns `Ok(None)`.
const MAX_MESSAGE_SIZE: usize = 100_000_000;

/// Write one bitcode-encoded message with a 4-byte little-endian
/// length prefix.
pub async fn send<T: bitcode::Encode>(stream: &mut UnixStream, msg: &T) -> anyhow::Result<()> {
    let bytes = bitcode::encode(msg);
    let len = (bytes.len() as u32).to_le_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Read one bitcode-encoded message preceded by a 4-byte length.
/// Returns `Ok(None)` on a framing error (zero / oversized length),
/// `Err` on socket-level failures, `Ok(Some(_))` on success.
pub async fn read<T: for<'a> bitcode::Decode<'a>>(
    stream: &mut UnixStream,
) -> anyhow::Result<Option<T>> {
    let len = read_len(stream).await?;
    if !is_valid_size(len) {
        return Ok(None);
    }
    let bytes = read_bytes(stream, len).await?;
    Ok(Some(bitcode::decode(&bytes)?))
}

async fn read_len(stream: &mut UnixStream) -> anyhow::Result<usize> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;
    Ok(u32::from_le_bytes(buf) as usize)
}

async fn read_bytes(stream: &mut UnixStream, len: usize) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

fn is_valid_size(len: usize) -> bool {
    len > 0 && len <= MAX_MESSAGE_SIZE
}
