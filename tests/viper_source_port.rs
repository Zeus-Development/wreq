//! VIPER-PATCH(local-port-bind): fork tests. A client's source port choice
//! is bound before connect, asked again when its port is in use, left to
//! the OS once it answers `None`, and a connector layer reads the socket's
//! addresses.

use std::{
    future::Future,
    net::{SocketAddr, TcpListener as StdListener},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tower::{BoxError, Layer, Service};
use wreq::{Client, Conn, Unnameable};

/// A server on loopback answering each request with an empty 200 and
/// closing; it records each client's address.
async fn server() -> (SocketAddr, Arc<Mutex<Vec<SocketAddr>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peers = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&peers);
    tokio::spawn(async move {
        while let Ok((mut stream, peer)) = listener.accept().await {
            seen.lock().unwrap().push(peer);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let answer = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                let _ = stream.write_all(answer).await;
            });
        }
    });
    (addr, peers)
}

/// A port free on every address now (bound and released).
fn free_port() -> u16 {
    StdListener::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A hook answering `ports` in order, one per try, recording each question.
fn hook(
    ports: Vec<u16>,
) -> (
    impl Fn(SocketAddr, u32) -> Option<u16> + Send + Sync + 'static,
    Arc<Mutex<Vec<(SocketAddr, u32)>>>,
) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&asked);
    let choose = move |peer: SocketAddr, attempt: u32| {
        record.lock().unwrap().push((peer, attempt));
        ports.get(attempt as usize).copied()
    };
    (choose, asked)
}

async fn get(client: &Client, addr: SocketAddr) {
    let response = client.get(format!("http://{addr}/")).send().await.unwrap();
    assert_eq!(response.status(), 200);
}

/// The chosen port is the one the server sees, asked with the peer.
#[tokio::test]
async fn a_chosen_port_is_the_one_the_server_sees() {
    let (addr, peers) = server().await;
    let port = free_port();
    let (choose, asked) = hook(vec![port]);
    let client = Client::builder()
        .no_proxy()
        .tcp_source_port(choose)
        .build()
        .unwrap();
    get(&client, addr).await;
    assert_eq!(peers.lock().unwrap()[0].port(), port);
    assert_eq!(*asked.lock().unwrap(), [(addr, 0)]);
}

/// A port in use asks again with the next try number.
#[tokio::test]
async fn a_port_in_use_asks_again_with_the_next_try() {
    let (addr, peers) = server().await;
    let busy = StdListener::bind("0.0.0.0:0").unwrap();
    let taken = busy.local_addr().unwrap().port();
    let port = free_port();
    let (choose, asked) = hook(vec![taken, port]);
    let client = Client::builder()
        .no_proxy()
        .tcp_source_port(choose)
        .build()
        .unwrap();
    get(&client, addr).await;
    assert_eq!(peers.lock().unwrap()[0].port(), port);
    assert_eq!(*asked.lock().unwrap(), [(addr, 0), (addr, 1)]);
    drop(busy);
}

/// Once the hook answers `None`, the OS picks the port.
#[tokio::test]
async fn with_no_port_left_the_os_picks_one() {
    let (addr, peers) = server().await;
    let busy = StdListener::bind("0.0.0.0:0").unwrap();
    let taken = busy.local_addr().unwrap().port();
    let (choose, asked) = hook(vec![taken]);
    let client = Client::builder()
        .no_proxy()
        .tcp_source_port(choose)
        .build()
        .unwrap();
    get(&client, addr).await;
    assert_ne!(peers.lock().unwrap()[0].port(), taken);
    assert_eq!(*asked.lock().unwrap(), [(addr, 0), (addr, 1)]);
    drop(busy);
}

/// The addresses a connector layer read.
#[derive(Clone, Default)]
struct Addresses(Arc<Mutex<Vec<Option<(SocketAddr, SocketAddr)>>>>);

#[derive(Clone)]
struct Reading<S>(S, Addresses);

impl<S> Layer<S> for Addresses {
    type Service = Reading<S>;
    fn layer(&self, inner: S) -> Reading<S> {
        Reading(inner, self.clone())
    }
}

impl<S> Service<Unnameable> for Reading<S>
where
    S: Service<Unnameable, Response = Conn, Error = BoxError>,
    S::Future: Send + 'static,
{
    type Response = Conn;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Conn, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, target: Unnameable) -> Self::Future {
        let seen = self.1.clone();
        let connecting = self.0.call(target);
        Box::pin(async move {
            let conn = connecting.await?;
            seen.0.lock().unwrap().push(conn.addresses());
            Ok(conn)
        })
    }
}

/// A connector layer reads the chosen local port and the peer.
#[tokio::test]
async fn a_connector_layer_reads_the_sockets_addresses() {
    let (addr, _) = server().await;
    let port = free_port();
    let (choose, _) = hook(vec![port]);
    let seen = Addresses::default();
    let client = Client::builder()
        .no_proxy()
        .tcp_source_port(choose)
        .connector_layer(seen.clone())
        .build()
        .unwrap();
    get(&client, addr).await;
    let read = seen.0.lock().unwrap().clone();
    let (local, peer) = read[0].expect("a TCP connection has addresses");
    assert_eq!((local.port(), peer), (port, addr));
}
