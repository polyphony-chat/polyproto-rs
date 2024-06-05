// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use http::HeaderMap;
use httptest::matchers::request;
use httptest::responders::json_encoded;
use httptest::{Expectation, Server};
use polyproto::api::core::current_unix_time;
use polyproto::api::HttpClient;
use polyproto::types::routes::core::v1::GET_CHALLENGE_STRING;
use serde_json::json;

async fn setup_example() -> Server {
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path(
            GET_CHALLENGE_STRING.method.as_str(),
            GET_CHALLENGE_STRING.path,
        ))
        .respond_with(json_encoded(json!({
            "challenge": "abcd".repeat(8),
            "expires": current_unix_time() + 100
        }))),
    );
    server
}

#[tokio::main]
async fn main() {
    let server = setup_example().await;
    let url = format!("http://{}", server.addr());

    // The actual example starts here.
    // Create a new HTTP client
    let mut client = HttpClient::new(&url).unwrap();
    // Add an authorization header to the client
    client.headers({
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "my_secret_token".parse().unwrap());
        headers
    });
    // You can now use the client to make requests to the polyproto home server!
    // Routes are documented under <https://docs.polyphony.chat/APIs/core/>, and each route has a
    // corresponding method in the `HttpClient` struct. For example, if we wanted to get a challenge
    // string from the server, we would call:
    let challenge = client.get_challenge_string().await.unwrap();
    println!("Challenge string: {}", challenge.challenge);
    println!("Challenge expires at UNIX timestamp: {}", challenge.expires);
}

#[test]
fn test_example() {}
