// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::str::FromStr;
use std::time::Duration;

use der::asn1::{Uint, UtcTime};
use httptest::matchers::request::method_path;
use httptest::matchers::{eq, json_decoded, request};
use httptest::responders::{json_encoded, status_code};
use httptest::*;
use polyproto::certs::capabilities::Capabilities;
use polyproto::certs::idcert::IdCert;
use polyproto::certs::idcsr::IdCsr;
use polyproto::types::routes::core::v1::{GET_CHALLENGE_STRING, ROTATE_SERVER_IDENTITY_KEY};
use polyproto::Name;
use serde_json::json;
use x509_cert::time::{Time, Validity};

use crate::common::{init_logger, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};

/// Correctly format the server URL for the test.
fn server_url(server: &Server) -> String {
    format!("http://{}", server.addr())
}

#[tokio::test]
async fn get_challenge_string() {
    init_logger();
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path(
            GET_CHALLENGE_STRING.method.as_str(),
            GET_CHALLENGE_STRING.path,
        ))
        .respond_with(json_encoded(json!({
            "challenge": "a".repeat(32),
            "expires": 1
        }))),
    );
    let url = server_url(&server);
    let client = polyproto::api::HttpClient::new(&url).unwrap();
    let challenge_string = client.get_challenge_string().await.unwrap();
    assert_eq!(challenge_string.challenge, "a".repeat(32));
    assert_eq!(challenge_string.expires, 1);
}

#[tokio::test]

async fn rotate_server_identity_key() {
    init_logger();
    let mut csprng = rand::rngs::OsRng;
    let subject = Name::from_str("CN=root,DC=polyphony,DC=chat").unwrap();
    let priv_key = Ed25519PrivateKey::gen_keypair(&mut csprng);
    let id_csr = IdCsr::<Ed25519Signature, Ed25519PublicKey>::new(
        &subject,
        &priv_key,
        &Capabilities::default_home_server(),
        Some(polyproto::certs::Target::HomeServer),
    )
    .unwrap();
    let id_cert = IdCert::from_ca_csr(
        id_csr,
        &priv_key,
        Uint::new(&[8]).unwrap(),
        subject,
        Validity {
            not_before: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_secs(10)).unwrap(),
            ),
            not_after: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_secs(1000)).unwrap(),
            ),
        },
    )
    .unwrap();
    let cert_pem = id_cert.to_pem(der::pem::LineEnding::LF).unwrap();
    let server = Server::run();
    server.expect(
        Expectation::matching(method_path(
            ROTATE_SERVER_IDENTITY_KEY.method.as_str(),
            ROTATE_SERVER_IDENTITY_KEY.path,
        ))
        .respond_with(json_encoded(json!(cert_pem))),
    );
    let url = server_url(&server);
    let client = polyproto::api::HttpClient::new(&url).unwrap();
    let cert = client
        .rotate_server_identity_key::<Ed25519Signature, Ed25519PublicKey>()
        .await
        .unwrap();
    assert_eq!(cert.to_pem(der::pem::LineEnding::LF).unwrap(), cert_pem);
}
