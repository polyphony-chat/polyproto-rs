// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use httptest::matchers::request;
use httptest::responders::json_encoded;
use httptest::*;
use serde_json::json;

use crate::common::init_logger;

/// Correctly format the server URL for the test.
fn server_url(server: &Server) -> String {
    format!("http://{}", server.addr())
}

#[tokio::test]
async fn get_challenge_string() {
    init_logger();
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path("GET", "/.p2/core/v1/challenge")).respond_with(
            json_encoded(json!({
                "challenge": "a".repeat(32),
                "expires": 1
            })),
        ),
    );
    let url = server_url(&server);
    dbg!(url.clone());
    let client = polyproto::api::HttpClient::new(&url).unwrap();
    let challenge_string = client.get_challenge_string().await.unwrap();
    assert_eq!(challenge_string.challenge, "a".repeat(32));
    assert_eq!(challenge_string.expires, 1);
}
