use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
use hyper::upgrade::Upgraded;
use pingora::protocols::raw_connect::ProxyDigest;
use pingora::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

/// Adapts Hyper's upgraded CONNECT stream to Pingora's custom-session IO
/// requirements. The stream has no raw TCP descriptor after Hyper upgrades it,
/// so socket and proxy digests are deliberately unavailable.
pub struct MitmIo {
    inner: DuplexStream,
    id: UniqueIDType,
}

static NEXT_MITM_IO_ID: AtomicU64 = AtomicU64::new(1);

impl MitmIo {
    pub fn new(upgraded: Upgraded) -> Self {
        // Hyper deliberately erases Sync from its upgraded transport. Keep
        // that transport in this one bridge task and give Pingora the other
        // side of a Tokio duplex stream, whose API meets Pingora's IO bounds.
        let (stream, mut bridge) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
            let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut bridge).await;
        });
        // `Upgraded` intentionally hides its original file descriptor. Pingora
        // only requires a unique connection identifier here, so provide a
        // process-local synthetic ID rather than pretending the duplex stream
        // has a usable raw socket.
        let id = NEXT_MITM_IO_ID.fetch_add(1, Ordering::Relaxed) as UniqueIDType;
        MitmIo { inner: stream, id }
    }
}

impl fmt::Debug for MitmIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("MitmIo").finish_non_exhaustive()
    }
}

impl AsyncRead for MitmIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for MitmIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, buffers)
    }
}

#[async_trait]
impl Shutdown for MitmIo {
    async fn shutdown(&mut self) {
        let _ = AsyncWriteExt::shutdown(&mut self.inner).await;
    }
}

impl UniqueID for MitmIo {
    fn id(&self) -> UniqueIDType {
        self.id
    }
}

impl Ssl for MitmIo {}

impl GetTimingDigest for MitmIo {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        Vec::new()
    }
}

impl GetProxyDigest for MitmIo {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        None
    }
}

impl GetSocketDigest for MitmIo {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        None
    }
}

impl Peek for MitmIo {}
