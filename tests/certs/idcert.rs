// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#![allow(unused)]

use std::str::FromStr;
use std::time::Duration;

use der::asn1::{BitString, Ia5String, Uint, UtcTime};
use der::{Decode, Encode};
use ed25519_dalek::{Signature as Ed25519DalekSignature, Signer, SigningKey, VerifyingKey};
use polyproto::certs::capabilities::{self, Capabilities};
use polyproto::certs::idcert::IdCert;
use polyproto::certs::{PublicKeyInfo, Target};
use polyproto::errors::composite::ConversionError;
use polyproto::key::{PrivateKey, PublicKey};
use polyproto::signature::Signature;
use rand::rngs::OsRng;
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SignatureBitStringEncoding};
use thiserror::Error;
use x509_cert::attr::Attributes;
use x509_cert::name::RdnSequence;
use x509_cert::request::CertReq;
use x509_cert::time::{Time, Validity};
use x509_cert::Certificate;

use crate::common::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
        Uint::new(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str(
            "CN=root,DC=polyphony,DC=chat,UID=root@polyphony.chat,uniqueIdentifier=root",
        )
        .unwrap(),
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
    let cert_data = cert.clone().to_der().unwrap();
    let data = Certificate::try_from(cert).unwrap().to_der().unwrap();
    assert_eq!(cert_data, data);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
        Uint::new(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("CN=root,DC=polyphony,DC=chat").unwrap(),
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
    let cert_data = cert.clone().to_der().unwrap();
    let data = Certificate::try_from(cert).unwrap().to_der().unwrap();
    assert_eq!(cert_data, data);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
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
        Uint::new(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str(
            "CN=root,DC=polyphony,DC=chat,UID=root@polyphony.chat,uniqueIdentifier=root",
        )
        .unwrap(),
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
    let cert_data = cert.clone().to_der().unwrap();
    let data = Certificate::try_from(cert).unwrap().to_der().unwrap();
    assert_eq!(cert_data, data);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn cert_from_pem() {
    init_logger();
    let mut csprng = rand::rngs::OsRng;
    let priv_key = Ed25519PrivateKey::gen_keypair(&mut csprng);

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
        Uint::new(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str(
            "CN=root,DC=polyphony,DC=chat,UID=root@polyphony.chat,uniqueIdentifier=root",
        )
        .unwrap(),
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
    let data = cert.clone().to_pem(der::pem::LineEnding::LF).unwrap();
    let cert_from_pem = IdCert::from_pem(&data, Some(polyproto::certs::Target::Actor)).unwrap();
    log::trace!(
        "Cert from pem key usages: {:#?}",
        cert_from_pem.id_cert_tbs.capabilities.key_usage.key_usages
    );
    assert_eq!(cert_from_pem, cert);

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
        Uint::new(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("CN=root,DC=polyphony,DC=chat").unwrap(),
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
    let data = cert.clone().to_pem(der::pem::LineEnding::LF).unwrap();
    let cert_from_pem =
        IdCert::from_pem(&data, Some(polyproto::certs::Target::HomeServer)).unwrap();
    log::trace!(
        "Cert from pem key usages: {:#?}",
        cert_from_pem.id_cert_tbs.capabilities.key_usage.key_usages
    );
    assert_eq!(cert_from_pem, cert);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn cert_from_der() {
    init_logger();
    let mut csprng = rand::rngs::OsRng;
    let priv_key = Ed25519PrivateKey::gen_keypair(&mut csprng);

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
        Uint::new(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str(
            "CN=root,DC=polyphony,DC=chat,UID=root@polyphony.chat,uniqueIdentifier=root",
        )
        .unwrap(),
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
    let data = cert.clone().to_der().unwrap();
    let cert_from_der = IdCert::from_der(&data, Some(polyproto::certs::Target::Actor)).unwrap();
    log::trace!(
        "Cert from pem key usages: {:#?}",
        cert_from_der.id_cert_tbs.capabilities.key_usage.key_usages
    );
    assert_eq!(cert_from_der, cert);

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
        Uint::new(&8932489u64.to_be_bytes()).unwrap(),
        RdnSequence::from_str("CN=root,DC=polyphony,DC=chat").unwrap(),
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
    let data = cert.clone().to_der().unwrap();
    let cert_from_der =
        IdCert::from_der(&data, Some(polyproto::certs::Target::HomeServer)).unwrap();
    log::trace!(
        "Cert from pem key usages: {:#?}",
        cert_from_der.id_cert_tbs.capabilities.key_usage.key_usages
    );
    assert_eq!(cert_from_der, cert);
}
