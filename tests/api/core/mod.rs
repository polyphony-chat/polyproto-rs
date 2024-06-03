// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use der::asn1::{GeneralizedTime, Uint};
use httptest::matchers::request::method_path;
use httptest::matchers::{eq, json_decoded, matches, request};
use httptest::responders::{json_encoded, status_code};
use httptest::*;
use polyproto::api::core::current_unix_time;
use polyproto::certs::capabilities::Capabilities;
use polyproto::certs::idcert::IdCert;
use polyproto::certs::idcsr::IdCsr;
use polyproto::certs::SessionId;
use polyproto::key::PublicKey;
use polyproto::types::routes::core::v1::{
    DELETE_SESSION, GET_ACTOR_IDCERTS, GET_CHALLENGE_STRING, GET_SERVER_PUBLIC_IDCERT,
    GET_SERVER_PUBLIC_KEY, ROTATE_SERVER_IDENTITY_KEY, ROTATE_SESSION_IDCERT,
    UPDATE_SESSION_IDCERT, UPLOAD_ENCRYPTED_PKM,
};
use serde_json::json;
use x509_cert::time::Validity;

use crate::common::{
    actor_id_cert, actor_subject, default_validity, gen_priv_key, home_server_id_cert,
    home_server_subject, init_logger, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
};

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
    let home_server_signing_key = gen_priv_key();
    let id_csr = IdCsr::new(
        &home_server_subject(),
        &home_server_signing_key,
        &Capabilities::default_home_server(),
        Some(polyproto::certs::Target::HomeServer),
    )
    .unwrap();
    let id_cert = IdCert::from_ca_csr(
        id_csr,
        &home_server_signing_key,
        Uint::new(9u64.to_be_bytes().as_slice()).unwrap(),
        home_server_subject(),
        Validity {
            not_before: x509_cert::time::Time::GeneralTime(
                GeneralizedTime::from_unix_duration(std::time::Duration::new(
                    current_unix_time() - 1000,
                    0,
                ))
                .unwrap(),
            ),
            not_after: x509_cert::time::Time::GeneralTime(
                GeneralizedTime::from_unix_duration(std::time::Duration::new(
                    current_unix_time() + 1000,
                    0,
                ))
                .unwrap(),
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

#[tokio::test]
async fn get_server_public_key() {
    init_logger();
    let mut csprng = rand::rngs::OsRng;
    let priv_key = Ed25519PrivateKey::gen_keypair(&mut csprng);
    let public_key_info = priv_key.public_key.public_key_info();
    let pem = public_key_info.to_pem(der::pem::LineEnding::LF).unwrap();
    log::debug!("Generated Public Key:\n{}", pem);
    let server = Server::run();
    server.expect(
        Expectation::matching(method_path(
            GET_SERVER_PUBLIC_KEY.method.as_str(),
            GET_SERVER_PUBLIC_KEY.path,
        ))
        .respond_with(json_encoded(json!(public_key_info
            .to_pem(der::pem::LineEnding::LF)
            .unwrap()))),
    );
    let url = server_url(&server);
    let client = polyproto::api::HttpClient::new(&url).unwrap();
    let public_key = client.get_server_public_key_info(None).await.unwrap();
    log::debug!(
        "Received Public Key:\n{}",
        public_key.to_pem(der::pem::LineEnding::LF).unwrap()
    );
    assert_eq!(
        public_key.public_key_bitstring,
        priv_key.public_key.public_key_info().public_key_bitstring
    );
}

#[tokio::test]
async fn get_server_id_cert() {
    init_logger();
    let id_cert = home_server_id_cert();
    let cert_pem = id_cert.to_pem(der::pem::LineEnding::LF).unwrap();
    let server = Server::run();
    let url = server_url(&server);
    let client = polyproto::api::HttpClient::new(&url).unwrap();
    server.expect(
        Expectation::matching(all_of![
            request::method(GET_SERVER_PUBLIC_IDCERT.method.as_str()),
            request::path(GET_SERVER_PUBLIC_IDCERT.path),
            request::body(json_decoded(eq(json!({"timestamp": 10})))),
        ])
        .respond_with(json_encoded(json!(cert_pem))),
    );

    let cert = client
        .get_server_id_cert::<Ed25519Signature, Ed25519PublicKey>(Some(10))
        .await
        .unwrap();
    assert_eq!(cert.to_pem(der::pem::LineEnding::LF).unwrap(), cert_pem);
}

#[tokio::test]
async fn get_actor_id_certs() {
    init_logger();
    let id_certs = {
        let mut vec: Vec<IdCert<Ed25519Signature, Ed25519PublicKey>> = Vec::new();
        for _ in 0..5 {
            let cert = actor_id_cert("flori");
            vec.push(cert);
        }
        vec
    };

    let certs_pem: Vec<String> = id_certs
        .into_iter()
        .map(|cert| cert.to_pem(der::pem::LineEnding::LF).unwrap())
        .collect();

    let server = Server::run();
    let url = server_url(&server);
    let client = polyproto::api::HttpClient::new(&url).unwrap();

    server.expect(
        Expectation::matching(all_of![
            request::method(GET_ACTOR_IDCERTS.method.as_str()),
            request::path(matches(format!("^{}.*$", GET_ACTOR_IDCERTS.path))),
            request::body(json_decoded(eq(json!({
                "timestamp": 12345,
                "session_id": "cool_session_id"
            }))))
        ])
        .respond_with(json_encoded(json!([{
            "id_cert": certs_pem[0],
            "invalidated": false
        }]))),
    );

    let certs = client
        .get_actor_id_certs::<Ed25519Signature, Ed25519PublicKey>(
            "flori@polyphony.chat",
            Some(12345),
            Some(&SessionId::new_validated("cool_session_id").unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(
        certs[0]
            .id_cert
            .clone()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap(),
        certs_pem[0]
    );
    assert!(!certs[0].invalidated);

    server.expect(
        Expectation::matching(all_of![
            request::method(GET_ACTOR_IDCERTS.method.as_str()),
            request::path(matches(format!("^{}.*$", GET_ACTOR_IDCERTS.path))),
        ])
        .respond_with(json_encoded(json!([{
            "id_cert": certs_pem[0],
            "invalidated": false
        }]))),
    );
    let certs = client
        .get_actor_id_certs::<Ed25519Signature, Ed25519PublicKey>(
            "flori@polyphony.chat",
            Some(12345),
            Some(&SessionId::new_validated("cool_session_id").unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(
        certs[0]
            .id_cert
            .clone()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap(),
        certs_pem[0]
    );
    assert!(!certs[0].invalidated);

    server.expect(
        Expectation::matching(all_of![
            request::method(GET_ACTOR_IDCERTS.method.as_str()),
            request::path(matches(format!("^{}.*$", GET_ACTOR_IDCERTS.path))),
            request::body(json_decoded(eq(json!({
                "timestamp": 12345            }))))
        ])
        .respond_with(json_encoded(json!([{
            "id_cert": certs_pem[0],
            "invalidated": false
        }]))),
    );

    let certs = client
        .get_actor_id_certs::<Ed25519Signature, Ed25519PublicKey>(
            "flori@polyphony.chat",
            Some(12345),
            None,
        )
        .await
        .unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(
        certs[0]
            .id_cert
            .clone()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap(),
        certs_pem[0]
    );
    assert!(!certs[0].invalidated);

    server.expect(
        Expectation::matching(all_of![
            request::method(GET_ACTOR_IDCERTS.method.as_str()),
            request::path(matches(format!("^{}.*$", GET_ACTOR_IDCERTS.path))),
            request::body(json_decoded(eq(json!({
                "session_id": "cool_session_id"
            }))))
        ])
        .respond_with(json_encoded(json!([{
            "id_cert": certs_pem[0],
            "invalidated": false
        }]))),
    );

    let certs = client
        .get_actor_id_certs::<Ed25519Signature, Ed25519PublicKey>(
            "flori@polyphony.chat",
            None,
            Some(&SessionId::new_validated("cool_session_id").unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(
        certs[0]
            .id_cert
            .clone()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap(),
        certs_pem[0]
    );
    assert!(!certs[0].invalidated);
}

#[tokio::test]
async fn update_session_id_cert() {
    init_logger();
    let id_cert = actor_id_cert("flori");
    let cert_pem = id_cert.clone().to_pem(der::pem::LineEnding::LF).unwrap();
    let server = Server::run();
    server.expect(
        Expectation::matching(all_of![
            request::method(UPDATE_SESSION_IDCERT.method.to_string()),
            request::path(UPDATE_SESSION_IDCERT.path),
            request::body(cert_pem)
        ])
        .respond_with(status_code(201)),
    );
    let url = server_url(&server);
    let client = polyproto::api::HttpClient::new(&url).unwrap();
    client
        .update_session_id_cert::<Ed25519Signature, Ed25519PublicKey>(id_cert)
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_session() {
    init_logger();
    let server = Server::run();
    server.expect(
        Expectation::matching(all_of![
            request::method(DELETE_SESSION.method.to_string()),
            request::path(DELETE_SESSION.path),
            request::body(json_decoded(eq(json!({
                "session_id": "cool_session_id"
            }))))
        ])
        .respond_with(status_code(204)),
    );
    let url = server_url(&server);
    let client = polyproto::api::HttpClient::new(&url).unwrap();
    client
        .delete_session(&SessionId::new_validated("cool_session_id").unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn rotate_session_id_cert() {
    init_logger();
    let actor_signing_key = gen_priv_key();
    let home_server_signing_key = gen_priv_key();
    let id_csr = IdCsr::new(
        &actor_subject("flori"),
        &actor_signing_key,
        &Capabilities::default_actor(),
        Some(polyproto::certs::Target::Actor),
    )
    .unwrap();
    let id_cert = IdCert::from_actor_csr(
        id_csr.clone(),
        &home_server_signing_key,
        Uint::new(&[8]).unwrap(),
        home_server_subject(),
        default_validity(),
    )
    .unwrap();
    let csr_pem = id_csr.clone().to_pem(der::pem::LineEnding::LF).unwrap();
    let server = Server::run();
    server.expect(
        Expectation::matching(all_of![
            request::method(ROTATE_SESSION_IDCERT.method.to_string()),
            request::path(ROTATE_SESSION_IDCERT.path),
            request::body(csr_pem)
        ])
        .respond_with(json_encoded(json!({
            "id_cert": id_cert.to_pem(der::pem::LineEnding::LF).unwrap(),
            "token": "meow"
        }))),
    );
    let url = server_url(&server);
    let client = polyproto::api::HttpClient::new(&url).unwrap();
    client
        .rotate_session_id_cert::<Ed25519Signature, Ed25519PublicKey>(id_csr)
        .await
        .unwrap();
}

#[tokio::test]
async fn upload_encrypted_pkm() {
    init_logger();
    let key = gen_priv_key();
    let pkm = String::from_utf8_lossy(key.key.as_bytes()).to_string();
    let server = Server::run();
    server.expect(
        Expectation::matching(all_of![
            request::method(UPLOAD_ENCRYPTED_PKM.method.to_string()),
            request::path(UPLOAD_ENCRYPTED_PKM.path),
            request::body(json_decoded(eq(json!([
                {
                    "key_data": pkm,
                    "serial_number": "one"
                }
            ]))))
        ])
        .respond_with(status_code(201)),
    );
    // TODO: Rewrite this test
    /*     let url = server_url(&server);
    let client = polyproto::api::HttpClient::new(&url).unwrap();
    let encrypted_pkm = EncryptedPkm {
        serial_number: SessionId::new_validated("one").unwrap().into(),
        key_data: pkm,
    };
    client
        .upload_encrypted_pkm(vec![encrypted_pkm])
        .await
        .unwrap(); */
}

#[tokio::test]
async fn get_encrypted_pkm() {}
