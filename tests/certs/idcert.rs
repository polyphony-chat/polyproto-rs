// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(unused)]

use std::str::FromStr;
use std::time::Duration;

use der::asn1::{BitString, Ia5String, Uint, UtcTime};
use der::{Decode, Encode};
use ed25519_dalek::{Signature as Ed25519DalekSignature, Signer, SigningKey, VerifyingKey};
use polyproto::certs::capabilities::{self, Capabilities};
use polyproto::certs::idcert::IdCert;
use polyproto::certs::{PublicKeyInfo, Target};
use polyproto::errors::composite::CertificateConversionError;
use polyproto::key::{PrivateKey, PublicKey};
use polyproto::signature::Signature;
use polyproto::types::x509_cert::SerialNumber;
use rand::rngs::OsRng;
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SignatureBitStringEncoding};
use thiserror::Error;
use url::Url;
use x509_cert::Certificate;
use x509_cert::attr::Attributes;
use x509_cert::name::RdnSequence;
use x509_cert::request::CertReq;
use x509_cert::time::{Time, Validity};

use crate::common::{self, *};

test_all_platforms! {
fn test_create_actor_cert() {
    init_logger();
    let mut csprng = rand::rngs::OsRng;
    let priv_key = Ed25519PrivateKey::gen_keypair(&mut csprng);
    println!("Private Key is: {:?}", priv_key.key.to_bytes());
    println!("Public Key is: {:?}", priv_key.public_key.key.to_bytes());
    println!();
    let mut capabilities = Capabilities::default_actor();
    capabilities
        .key_usage
        .key_usages
        .push(capabilities::KeyUsage::CrlSign);
    let csr = polyproto::certs::idcsr::IdCsr::new(
        &RdnSequence::from_str(
            "CN=flori,DC=polyphony,DC=chat,UID=flori@polyphony.chat,uniqueIdentifier=client1",
        )
        .unwrap(),
        &priv_key,
        &capabilities,
        Some(Target::Actor),
    )
    .unwrap();
    let cert = IdCert::from_actor_csr(
        csr,
        &priv_key,
        SerialNumber::from_bytes_be(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("DC=polyphony,DC=chat").unwrap(),
        default_validity(),
    )
    .unwrap();
    let cert_data = cert.clone().to_der().unwrap();
    let data = Certificate::try_from(cert.clone())
        .unwrap()
        .to_der()
        .unwrap();
    assert_eq!(cert_data, data);
    assert!(cert
        .full_verify_actor(
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(100)).unwrap(),)
                .to_unix_duration()
                .as_secs(),
            priv_key.pubkey()
        )
        .is_ok());
    assert!(cert
        .full_verify_home_server(
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(100)).unwrap(),)
                .to_unix_duration()
                .as_secs(),
        )
        .is_err())
}
}

test_all_platforms! {
fn test_create_ca_cert() {
    init_logger();
    let mut csprng = rand::rngs::OsRng;
    let priv_key = Ed25519PrivateKey::gen_keypair(&mut csprng);
    println!("Private Key is: {:?}", priv_key.key.to_bytes());
    println!("Public Key is: {:?}", priv_key.public_key.key.to_bytes());
    println!();

    let csr = polyproto::certs::idcsr::IdCsr::new(
        &RdnSequence::from_str("CN=root,DC=polyphony,DC=chat").unwrap(),
        &priv_key,
        &Capabilities::default_home_server(),
        Some(Target::HomeServer),
    )
    .unwrap();
    let cert = IdCert::from_ca_csr(
        csr,
        &priv_key,
        SerialNumber::from_bytes_be(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("CN=root,DC=polyphony,DC=chat").unwrap(),
        default_validity(),
    )
    .unwrap();
    let cert_data = cert.clone().to_der().unwrap();
    let data = Certificate::try_from(cert.clone())
        .unwrap()
        .to_der()
        .unwrap();
    assert_eq!(cert_data, data);
    assert!(cert
        .full_verify_actor(
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(100)).unwrap(),)
                .to_unix_duration()
                .as_secs(),
            priv_key.pubkey()
        )
        .is_err());
    assert!(cert
        .full_verify_home_server(
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(100)).unwrap(),)
                .to_unix_duration()
                .as_secs(),
        )
        .is_ok())
}
}

test_all_platforms! {
fn mismatched_dcs_in_csr_and_cert() {
    init_logger();
    let mut csprng = rand::rngs::OsRng;
    let priv_key = Ed25519PrivateKey::gen_keypair(&mut csprng);
    println!("Private Key is: {:?}", priv_key.key.to_bytes());
    println!("Public Key is: {:?}", priv_key.public_key.key.to_bytes());
    println!();

    let csr = polyproto::certs::idcsr::IdCsr::new(
        &RdnSequence::from_str(
            "CN=flori,DC=polyphony,DC=chat,UID=flori@polyphony.chat,uniqueIdentifier=client1",
        )
        .unwrap(),
        &priv_key,
        &Capabilities::default_actor(),
        Some(Target::Actor),
    )
    .unwrap();
    let cert = IdCert::from_actor_csr(
        csr,
        &priv_key,
        SerialNumber::from_bytes_be(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("DC=polyphony,DC=chat").unwrap(),
        default_validity(),
    )
    .unwrap();
    let cert_data = cert.clone().to_der().unwrap();
    let data = Certificate::try_from(cert).unwrap().to_der().unwrap();
    assert_eq!(cert_data, data);
}
}

test_all_platforms! {
fn cert_from_pem() {
    init_logger();
    let mut csprng = rand::rngs::OsRng;
    let priv_key_actor = Ed25519PrivateKey::gen_keypair(&mut csprng);
    let priv_key_home_server = Ed25519PrivateKey::gen_keypair(&mut csprng);

    let csr = polyproto::certs::idcsr::IdCsr::new(
        &RdnSequence::from_str(
            "CN=flori,DC=polyphony,DC=chat,UID=flori@polyphony.chat,uniqueIdentifier=client1",
        )
        .unwrap(),
        &priv_key_actor,
        &Capabilities::default_actor(),
        Some(Target::Actor),
    )
    .unwrap();

    let cert = IdCert::from_actor_csr(
        csr,
        &priv_key_home_server,
        SerialNumber::from_bytes_be(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("DC=polyphony,DC=chat").unwrap(),
        default_validity(),
    )
    .unwrap();
    let data = cert.clone().to_pem(der::pem::LineEnding::LF).unwrap();
    let cert_from_pem = IdCert::from_pem(
        &data,
        polyproto::certs::Target::Actor,
        10,
        &priv_key_home_server.public_key,
    )
    .unwrap();
    log::trace!(
        "Cert from pem key usages: {:#?}",
        cert_from_pem.id_cert_tbs.capabilities.key_usage.key_usages
    );
    assert_eq!(cert_from_pem, cert);

    let csr = polyproto::certs::idcsr::IdCsr::new(
        &RdnSequence::from_str("CN=root,DC=polyphony,DC=chat").unwrap(),
        &priv_key_home_server,
        &Capabilities::default_home_server(),
        Some(Target::HomeServer),
    )
    .unwrap();
    let cert = IdCert::from_ca_csr(
        csr,
        &priv_key_home_server,
        SerialNumber::from_bytes_be(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("CN=root,DC=polyphony,DC=chat").unwrap(),
        default_validity(),
    )
    .unwrap();
    let data = cert.clone().to_pem(der::pem::LineEnding::LF).unwrap();
    let cert_from_pem = IdCert::from_pem(
        &data,
        polyproto::certs::Target::HomeServer,
        10,
        &priv_key_home_server.public_key,
    )
    .unwrap();
    log::trace!(
        "Cert from pem key usages: {:#?}",
        cert_from_pem.id_cert_tbs.capabilities.key_usage.key_usages
    );
    assert_eq!(cert_from_pem, cert);
}
}

test_all_platforms! {
fn cert_from_der() {
    init_logger();
    let mut csprng = rand::rngs::OsRng;
    let priv_key_actor = Ed25519PrivateKey::gen_keypair(&mut csprng);
    let priv_key_home_server = Ed25519PrivateKey::gen_keypair(&mut csprng);

    let csr = polyproto::certs::idcsr::IdCsr::new(
        &RdnSequence::from_str(
            "CN=flori,DC=polyphony,DC=chat,UID=flori@polyphony.chat,uniqueIdentifier=client1",
        )
        .unwrap(),
        &priv_key_actor,
        &Capabilities::default_actor(),
        Some(Target::Actor),
    )
    .unwrap();

    let cert = IdCert::from_actor_csr(
        csr,
        &priv_key_home_server,
        SerialNumber::from_bytes_be(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("DC=polyphony,DC=chat").unwrap(),
        default_validity(),
    )
    .unwrap();
    let data = cert.clone().to_der().unwrap();
    let cert_from_der = IdCert::from_der(
        &data,
        polyproto::certs::Target::Actor,
        10,
        &priv_key_home_server.public_key,
    )
    .unwrap();
    log::trace!(
        "Cert from pem key usages: {:#?}",
        cert_from_der.id_cert_tbs.capabilities.key_usage.key_usages
    );
    assert_eq!(cert_from_der, cert);

    // Actor cert ^
    // Home server cert v

    let csr = polyproto::certs::idcsr::IdCsr::new(
        &RdnSequence::from_str("CN=root,DC=polyphony,DC=chat").unwrap(),
        &priv_key_home_server,
        &Capabilities::default_home_server(),
        Some(Target::HomeServer),
    )
    .unwrap();
    let cert = IdCert::from_ca_csr(
        csr,
        &priv_key_home_server,
        SerialNumber::from_bytes_be(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("CN=root,DC=polyphony,DC=chat").unwrap(),
        default_validity(),
    )
    .unwrap();
    let data = cert.clone().to_der().unwrap();
    let cert_from_der = IdCert::from_der(
        &data,
        polyproto::certs::Target::HomeServer,
        10,
        &priv_key_home_server.public_key,
    )
    .unwrap();
    log::trace!(
        "Cert from pem key usages: {:#?}",
        cert_from_der.id_cert_tbs.capabilities.key_usage.key_usages
    );
    assert_eq!(cert_from_der, cert);
}
}

test_all_platforms! {
fn issuer_url() {
    init_logger();
    let id_cert_actor = common::actor_id_cert("flori");
    let url = id_cert_actor.issuer_url().unwrap();
    assert_eq!(url, Url::parse("https://polyphony.chat").unwrap())
}
}

test_all_platforms! {
fn invalid_signature() {
    init_logger();
    let mut csprng = rand::rngs::OsRng;
    let priv_key_actor = Ed25519PrivateKey::gen_keypair(&mut csprng);
    let priv_key_home_server = Ed25519PrivateKey::gen_keypair(&mut csprng);

    let csr = polyproto::certs::idcsr::IdCsr::new(
        &RdnSequence::from_str(
            "CN=flori,DC=polyphony,DC=chat,UID=flori@polyphony.chat,uniqueIdentifier=client1",
        )
        .unwrap(),
        &priv_key_actor,
        &Capabilities::default_actor(),
        Some(Target::Actor),
    )
    .unwrap();

    let cert = IdCert::from_actor_csr(
        csr,
        &priv_key_home_server,
        SerialNumber::from_bytes_be(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("DC=polyphony,DC=chat").unwrap(),
        default_validity(),
    )
    .unwrap();
    let mut other_cert = cert.clone();
    other_cert.id_cert_tbs.serial_number = SerialNumber::from_bytes_be(&[12, 13, 11]).unwrap();
    assert!(other_cert
        .full_verify_actor(
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(100)).unwrap(),)
                .to_unix_duration()
                .as_secs(),
            &priv_key_home_server.public_key
        )
        .is_err());

    let csr = polyproto::certs::idcsr::IdCsr::new(
        &RdnSequence::from_str("CN=root,DC=polyphony,DC=chat").unwrap(),
        &priv_key_home_server,
        &Capabilities::default_home_server(),
        Some(Target::HomeServer),
    )
    .unwrap();
    let cert = IdCert::from_ca_csr(
        csr,
        &priv_key_home_server,
        SerialNumber::from_bytes_be(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("CN=root,DC=polyphony,DC=chat").unwrap(),
        default_validity(),
    )
    .unwrap();

    let mut other_cert = cert.clone();
    other_cert.id_cert_tbs.serial_number = SerialNumber::from_bytes_be(&[12, 13, 11]).unwrap();
    assert!(other_cert
        .full_verify_home_server(
            Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(100)).unwrap(),)
                .to_unix_duration()
                .as_secs()
        )
        .is_err());
}
}
