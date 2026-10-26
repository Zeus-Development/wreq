// VIPER-PATCH(response-bytes): an HTTP/1 request whose connection fails
// before the response head is complete learns whether any response byte
// had arrived (RFC 9112 section 9.3.1), for each way the connection can
// fail: an end of stream, a failed read and a failed write; on a reused
// connection, the earlier response's bytes never count for the next.

use std::{
    collections::VecDeque,
    convert::Infallible,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use futures_channel::mpsc;
use futures_util::{SinkExt, StreamExt};
use http::Request;
use http_body::Frame;
use http_body_util::{BodyExt, Empty, StreamBody};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::Notify,
};
use wreq_proto::conn::http1;

/// What the peer gives each read once the request head is written: bytes,
/// a failure, or nothing yet; an end of stream once the script is used up.
enum Read {
    Bytes(&'static [u8]),
    Fail(io::ErrorKind),
    Hang,
}

/// A peer that answers the request with its script. Each write after the
/// first fails with `write_fails`, if set; `read` is told once every
/// scripted byte was read.
struct Peer {
    writes: usize,
    write_fails: Option<io::ErrorKind>,
    reads: VecDeque<Read>,
    read: Arc<Notify>,
    waker: Option<Waker>,
}

impl Peer {
    fn new(reads: Vec<Read>) -> Self {
        Self {
            writes: 0,
            write_fails: None,
            reads: reads.into(),
            read: Arc::new(Notify::new()),
            waker: None,
        }
    }
}

impl AsyncRead for Peer {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let hangs = matches!(self.reads.front(), Some(Read::Hang));
        if hangs && self.writes > 0 {
            self.read.notify_one();
        }
        if hangs || self.writes == 0 {
            self.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        match self.reads.pop_front() {
            Some(Read::Bytes(bytes)) => buf.put_slice(bytes),
            Some(Read::Fail(kind)) => return Poll::Ready(Err(kind.into())),
            Some(Read::Hang) | None => {}
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Peer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes += 1;
        if let Some(kind) = self.write_fails.filter(|_| self.writes > 1) {
            return Poll::Ready(Err(kind.into()));
        }
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The error of a GET whose peer answers with `reads`.
async fn failure(reads: Vec<Read>) -> wreq_proto::Error {
    let (mut sender, conn) = http1::Builder::default()
        .handshake::<_, Empty<Bytes>>(Peer::new(reads))
        .await
        .expect("handshake");
    tokio::spawn(conn);
    let request = Request::get("/").body(Empty::new()).expect("request");
    let sent = sender.try_send_request(request).await;
    sent.map(|_| ())
        .expect_err("the request fails")
        .into_error()
}

/// The error of a POST whose body's second write fails with `kind` once
/// the peer has given `reads`.
async fn write_failure(reads: Vec<Read>, kind: io::ErrorKind) -> wreq_proto::Error {
    type Chunk = Result<Frame<Bytes>, Infallible>;
    let mut peer = Peer::new(reads);
    peer.write_fails = Some(kind);
    let read = Arc::clone(&peer.read);
    let (mut chunks, body) = mpsc::channel::<Chunk>(1);
    let (mut sender, conn) = http1::Builder::default()
        .handshake(peer)
        .await
        .expect("handshake");
    tokio::spawn(conn);
    let body = StreamBody::new(body.map(|chunk| chunk));
    let request = Request::post("/").body(body).expect("request");
    let sent = tokio::spawn(sender.try_send_request(request));
    read.notified().await;
    let chunk = Frame::data(Bytes::from_static(b"body"));
    chunks.send(Ok(chunk)).await.expect("the body is read");
    let sent = sent.await.expect("the request task");
    sent.map(|_| ())
        .expect_err("the request fails")
        .into_error()
}

const PARTIAL: &[u8] = b"HTTP/1.1 200 OK\r\nContent-";

/// The I/O error kind below `error`.
fn io_kind(error: &wreq_proto::Error) -> Option<io::ErrorKind> {
    let source = std::error::Error::source(error);
    source
        .and_then(|e| e.downcast_ref::<io::Error>())
        .map(io::Error::kind)
}

#[tokio::test]
async fn an_end_of_stream_tells_whether_a_response_began() {
    let none = failure(vec![]).await;
    assert!(none.is_incomplete_message(), "{none:?}");
    assert!(!none.received_response_bytes(), "{none:?}");
    for reads in [
        vec![Read::Bytes(PARTIAL)],
        vec![Read::Bytes(b"\r\n")],
        vec![Read::Bytes(b"HTTP/1.1 100 Continue\r\n\r\n")],
    ] {
        let some = failure(reads).await;
        assert!(some.is_incomplete_message(), "{some:?}");
        assert!(some.received_response_bytes(), "{some:?}");
    }
}

#[tokio::test]
async fn a_failed_read_tells_whether_a_response_began() {
    for kind in [
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted,
    ] {
        let none = failure(vec![Read::Fail(kind)]).await;
        let some = failure(vec![Read::Bytes(PARTIAL), Read::Fail(kind)]).await;
        for (error, bytes) in [(none, false), (some, true)] {
            assert_eq!(io_kind(&error), Some(kind), "{error:?}");
            assert_eq!(error.received_response_bytes(), bytes, "{error:?}");
        }
    }
}

#[tokio::test]
async fn a_failed_write_tells_whether_a_response_began() {
    let kind = io::ErrorKind::BrokenPipe;
    let none = write_failure(vec![Read::Hang], kind).await;
    let some = write_failure(vec![Read::Bytes(PARTIAL), Read::Hang], kind).await;
    for (error, bytes) in [(none, false), (some, true)] {
        assert_eq!(io_kind(&error), Some(kind), "{error:?}");
        assert_eq!(error.received_response_bytes(), bytes, "{error:?}");
    }
}

#[tokio::test]
async fn a_parse_error_counts_its_bytes() {
    let error = failure(vec![Read::Bytes(b"not http\r\n\r\n")]).await;
    assert!(error.is_parse(), "{error:?}");
    assert!(error.received_response_bytes(), "{error:?}");
}

/// Reads one request head from `server`.
async fn read_head(server: &mut DuplexStream) {
    let (mut head, mut buf) = (Vec::new(), [0_u8; 256]);
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = server.read(&mut buf).await.expect("read");
        assert!(n > 0, "the client closed");
        head.extend_from_slice(&buf[..n]);
    }
}

#[tokio::test]
async fn a_reused_connection_starts_afresh() {
    let (client, mut server) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        read_head(&mut server).await;
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        server.write_all(answer).await.expect("write");
        read_head(&mut server).await;
    });
    let (mut sender, conn) = http1::Builder::default()
        .handshake::<_, Empty<Bytes>>(client)
        .await
        .expect("handshake");
    tokio::spawn(conn);
    let get = || Request::get("/").body(Empty::new()).expect("request");
    let first = sender.try_send_request(get()).await;
    let first = first.map_err(|e| e.into_error()).expect("the first answer");
    first.into_body().collect().await.expect("the first body");
    sender.ready().await.expect("the connection is reused");
    let sent = sender.try_send_request(get()).await;
    let error = sent
        .map(|_| ())
        .expect_err("the request fails")
        .into_error();
    assert!(error.is_incomplete_message(), "{error:?}");
    assert!(!error.received_response_bytes(), "{error:?}");
}
