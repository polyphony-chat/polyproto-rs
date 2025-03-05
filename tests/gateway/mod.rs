// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn connect_tungstenite_smoke_test() {
    use std::sync::Arc;

    use polyproto::api::{HttpClient, Session};
    use polyproto::gateway::{backends, BackendBehavior};
    use url::Url;
    use ws_mock::ws_mock_server::WsMockServer;

    use crate::common::{Ed25519PrivateKey, Ed25519Signature};

    let server = WsMockServer::start().await;
    let tungstenite = backends::tungstenite::TungsteniteBackend::new();
    let session = Session::<Ed25519Signature, Ed25519PrivateKey>::new(
        &HttpClient::new().unwrap(),
        "none",
        Url::parse("http://127.0.0.1").unwrap(),
        None,
    );
    tungstenite
        .connect(Arc::new(session), &Url::parse(&server.uri().await).unwrap())
        .await
        .unwrap();
}
