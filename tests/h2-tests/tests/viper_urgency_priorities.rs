// VIPER-PATCH(h2-stream-priority): each request's HEADERS priority by its
// RFC 9218 urgency (RFC 9113 sections 5.3.1 and 5.3.2).

use h2::ext::{Urgency, UrgencyParent, UrgencyPriorities};
use h2::frame::{Frame, StreamDependency, StreamId};
use h2_support::prelude::*;

const WEIGHTS: [u8; 8] = [255, 219, 182, 146, 109, 73, 36, 0];

fn request(urgency: Option<u8>) -> Request<()> {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri("https://example.com/")
        .body(())
        .unwrap();
    if let Some(urgency) = urgency {
        let urgency = Urgency::new(urgency).unwrap();
        request.extensions_mut().insert(urgency);
    }
    request
}

/// The GET on `id` with the priority `(parent, weight, exclusive)`.
fn get(id: u32, priority: Option<(u32, u8, bool)>) -> frame::Headers {
    let Frame::Headers(mut headers) = frames::headers(id)
        .request("GET", "https://example.com/")
        .into()
    else {
        unreachable!()
    };
    if let Some((parent, weight, exclusive)) = priority {
        let dependency = StreamDependency::new(StreamId::from(parent), weight, exclusive);
        headers.set_stream_dependency(dependency);
    }
    headers.set_end_stream();
    headers
}

#[tokio::test]
async fn each_request_depends_on_the_newest_open_stream_at_the_nearest_urgency() {
    h2_support::trace_init!();
    let (io, mut srv) = mock::new();
    let priorities = UrgencyPriorities {
        weights: WEIGHTS,
        exclusive: true,
        parent: UrgencyParent::NearestOpen,
    };

    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);
        srv.recv_frame(get(1, Some((0, 255, true)))).await;
        // Its own urgency has none open, the more urgent one has stream 1.
        srv.recv_frame(get(3, Some((1, 219, true)))).await;
        srv.recv_frame(get(5, Some((3, 219, true)))).await;
        // No urgency is the default, 3: the nearest open above is stream 5.
        srv.recv_frame(get(7, Some((5, 146, true)))).await;
        srv.recv_frame(get(9, Some((7, 0, true)))).await;
        srv.send_frame(frames::headers(5).response(200).eos()).await;
        // Stream 5 is closed, so stream 3 is the newest open at urgency 1.
        srv.recv_frame(get(11, Some((3, 219, true)))).await;
        // Its own urgency first: stream 7, though stream 11 is newer.
        srv.recv_frame(get(13, Some((7, 146, true)))).await;
        for id in [11, 13, 1, 3, 7, 9] {
            srv.send_frame(frames::headers(id).response(200).eos())
                .await;
        }
        idle_ms(10).await;
    };

    let h2 = async move {
        let (mut client, mut h2) = client::Builder::new()
            .urgency_priorities(priorities)
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let mut held = Vec::new();
        for urgency in [Some(0), Some(1), Some(1), None] {
            held.push(client.send_request(request(urgency), true).unwrap().0);
        }
        held.push(client.send_request(request(Some(7)), true).unwrap().0);
        let third = held.remove(2);
        h2.drive(third).await.unwrap();
        let (last, _) = client.send_request(request(Some(1)), true).unwrap();
        let (own, _) = client.send_request(request(Some(3)), true).unwrap();
        h2.drive(last).await.unwrap();
        h2.drive(own).await.unwrap();
        for response in held {
            h2.drive(response).await.unwrap();
        }
        drop(client);
        h2.await.unwrap();
    };

    join(srv, h2).await;
}

#[tokio::test]
async fn the_root_parent_and_no_option() {
    h2_support::trace_init!();
    let (io, mut srv) = mock::new();
    let priorities = UrgencyPriorities {
        weights: WEIGHTS,
        exclusive: false,
        parent: UrgencyParent::Root,
    };

    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);
        srv.recv_frame(get(1, Some((0, 255, false)))).await;
        srv.recv_frame(get(3, Some((0, 109, false)))).await;
        srv.send_frame(frames::headers(1).response(200).eos()).await;
        srv.send_frame(frames::headers(3).response(200).eos()).await;
        idle_ms(10).await;
    };

    let h2 = async move {
        let (mut client, mut h2) = client::Builder::new()
            .urgency_priorities(priorities)
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let (first, _) = client.send_request(request(Some(0)), true).unwrap();
        let (second, _) = client.send_request(request(Some(4)), true).unwrap();
        h2.drive(first).await.unwrap();
        h2.drive(second).await.unwrap();
        drop(client);
        h2.await.unwrap();
    };

    join(srv, h2).await;
}

#[tokio::test]
async fn without_the_option_an_urgency_changes_nothing() {
    h2_support::trace_init!();
    let (io, mut srv) = mock::new();

    let srv = async move {
        let settings = srv.assert_client_handshake().await;
        assert_default_settings!(settings);
        srv.recv_frame(get(1, None)).await;
        srv.send_frame(frames::headers(1).response(200).eos()).await;
        idle_ms(10).await;
    };

    let h2 = async move {
        let (mut client, mut h2) = client::handshake(io).await.unwrap();
        let (response, _) = client.send_request(request(Some(0)), true).unwrap();
        h2.drive(response).await.unwrap();
        drop(client);
        h2.await.unwrap();
    };

    join(srv, h2).await;
}

#[test]
fn an_urgency_is_at_most_7() {
    assert_eq!(Urgency::new(7).map(Urgency::value), Some(7));
    assert_eq!(Urgency::new(8), None);
    assert_eq!(Urgency::default(), Urgency::DEFAULT);
    assert_eq!(Urgency::DEFAULT.value(), 3);
}
