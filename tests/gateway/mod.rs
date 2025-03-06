// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::common::{Ed25519PrivateKey, Ed25519Signature};

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn connect_tungstenite_hello() {
    use std::sync::Arc;

    use polyproto::api::{HttpClient, Session};
    use polyproto::gateway::{backends, BackendBehavior};
    use polyproto::types::gateway::payload::Hello;
    use polyproto::types::gateway::{CoreEvent, Payload};
    use serde_json::json;
    use tokio_tungstenite::tungstenite::Message;
    use url::Url;
    use ws_mock::ws_mock_server::{WsMock, WsMockServer};

    use crate::common;

    let server = WsMockServer::start().await;
    let (send, receive) = tokio::sync::mpsc::channel::<Message>(32);
    WsMock::new()
        .forward_from_channel(receive)
        .mount(&server)
        .await;

    common::init_logger();
    let tungstenite = backends::tungstenite::TungsteniteBackend::new();
    let session = Session::<Ed25519Signature, Ed25519PrivateKey>::new(
        &HttpClient::new().unwrap(),
        "none",
        Url::parse("http://127.0.0.1").unwrap(),
        None,
    );
    send.send(Message::Text(
        json!(CoreEvent::new(
            Payload::Hello(Hello {
                heartbeat_interval: 12345
            }),
            None
        ))
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    println!("sent data");
    tungstenite
        .connect(Arc::new(session), &Url::parse(&server.uri().await).unwrap())
        .await
        .unwrap();
}
