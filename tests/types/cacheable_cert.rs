// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use polyproto::api::cacheable_cert::CacheableIdCert;
use polyproto::certs::idcert::IdCert;
use polyproto::key::{PrivateKey, PublicKey};
use polyproto::signature::Signature;
use polyproto::types::der::asn1::Uint;
use polyproto::types::x509_cert::SerialNumber;

use crate::common::{self, Ed25519Signature, init_logger};
use crate::test_all_platforms;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn verify_cache_signature() {
    common::init_logger();
    let private_key = common::gen_priv_key();
    let public_key = private_key.pubkey();

    let some_cert = common::actor_id_cert("someactor");

    let mut cert_to_check = CacheableIdCert {
        cert: some_cert.clone().to_pem(der::pem::LineEnding::LF).unwrap(),
        invalidated_at: None,
        not_valid_before: 0,
        not_valid_after: u64::MAX,
        cache_signature: private_key
            .sign(
                (some_cert.id_cert_tbs.serial_number.clone().to_string()
                    + &0.to_string()
                    + &u64::MAX.to_string()
                    + "")
                    .as_bytes(),
            )
            .as_hex(),
    };

    let signature = cert_to_check.cache_signature.clone();
    public_key
        .verify_signature(
            &Ed25519Signature::try_from_hex(&signature).unwrap(),
            (some_cert.id_cert_tbs.serial_number.to_string()
                + &0.to_string()
                + &u64::MAX.to_string()
                + "")
                .as_bytes(),
        )
        .unwrap();

    assert!(cert_to_check.verify(public_key).is_ok());
    cert_to_check.invalidated_at = Some(1);
    assert!(cert_to_check.verify(public_key).is_err());
}

test_all_platforms! {
    fn verify_successful() {
        init_logger();
        let skey = common::Ed25519PrivateKey::gen_keypair(&mut rand::rngs::OsRng);
        let vkey = skey.public_key.clone();
        let cert = common::actor_id_cert("skyrina");
        let serial_number =
            cert.clone().id_cert_tbs.serial_number;

        let cacheable_cert = CacheableIdCert {
            cert: cert.to_pem(der::pem::LineEnding::LF).unwrap().to_string(),
            invalidated_at: None,
            not_valid_before: 1234,
            not_valid_after: 5678,
            cache_signature: skey.sign((serial_number.to_string() + &1234.to_string() + &5678.to_string() + "").as_bytes()).as_hex()
        };
        dbg!(serial_number.to_string() + &1234.to_string() + &5678.to_string() + "");
        assert!(vkey.verify_signature(&Ed25519Signature::try_from_hex(&cacheable_cert.cache_signature).unwrap(), (serial_number.to_string() + &1234.to_string() + &5678.to_string() + "").as_bytes()).is_ok());
        cacheable_cert.verify(&vkey).unwrap();
    }
}

test_all_platforms! {
    #[should_panic]
    fn verify_unsuccessful() {
        init_logger();
        let skey = common::Ed25519PrivateKey::gen_keypair(&mut rand::rngs::OsRng);
        let vkey = skey.public_key.clone();
        let cert = common::actor_id_cert("skyrina");
        let serial_number =
            cert.clone().id_cert_tbs.serial_number;
        let cacheable_cert = CacheableIdCert {
            cert: cert.to_pem(der::pem::LineEnding::LF).unwrap().to_string(),
            invalidated_at: None,
            not_valid_before: 123456,
            not_valid_after: 5678,
            cache_signature: skey.sign((serial_number.to_string() + &1234.to_string() + &5678.to_string() + "").as_bytes()).as_hex()
        };
        dbg!(serial_number.to_string() + &1234.to_string() + &5678.to_string() + "");
        assert!(vkey.verify_signature(&Ed25519Signature::try_from_hex(&cacheable_cert.cache_signature).unwrap(), (serial_number.to_string() + &1234.to_string() + &5678.to_string() + "").as_bytes()).is_err());
        cacheable_cert.verify(&vkey).unwrap();
    }
}

test_all_platforms! {
    #[should_panic]
    fn verify_unsuccessful_broken_serial_number() {
        init_logger();
        let skey = common::Ed25519PrivateKey::gen_keypair(&mut rand::rngs::OsRng);
        let vkey = skey.public_key.clone();
        let mut cert = common::actor_id_cert("skyrina");
        let serial_number =
            cert.clone().id_cert_tbs.serial_number;
        cert.id_cert_tbs.serial_number = SerialNumber::from_bytes_be(&[]).unwrap();
        let cacheable_cert = CacheableIdCert {
            cert: cert.to_pem(der::pem::LineEnding::LF).unwrap().to_string(),
            invalidated_at: None,
            not_valid_before: 1234,
            not_valid_after: 5678,
            cache_signature: skey.sign((serial_number.to_string() + &1234.to_string() + &5678.to_string() + "").as_bytes()).as_hex()
        };
        cacheable_cert.verify(&vkey).unwrap();
    }
}

test_all_platforms! {
    #[should_panic]
    fn verify_unsuccessful_bad_hex_signature() {
        init_logger();
        let skey = common::Ed25519PrivateKey::gen_keypair(&mut rand::rngs::OsRng);
        let vkey = skey.public_key.clone();
        let cert = common::actor_id_cert("skyrina");
        let serial_number =
            cert.clone().id_cert_tbs.serial_number;
        let cacheable_cert = CacheableIdCert {
            cert: cert.to_pem(der::pem::LineEnding::LF).unwrap().to_string(),
            invalidated_at: None,
            not_valid_before: 1234,
            not_valid_after: 5678,
            cache_signature: skey.sign((serial_number.to_string() + &1234.to_string() + &5678.to_string() + "").as_bytes()).as_hex() + "6789t5rygc4ghbm"
        };
        cacheable_cert.verify(&vkey).unwrap();
    }
}

test_all_platforms! {
    #[should_panic]
    fn verify_unsuccessful_bad_cert_pem() {
        init_logger();
        let skey = common::Ed25519PrivateKey::gen_keypair(&mut rand::rngs::OsRng);
        let vkey = skey.public_key.clone();
        let cert = common::actor_id_cert("skyrina");
        let serial_number =
            cert.clone().id_cert_tbs.serial_number;
        let cacheable_cert = CacheableIdCert {
            cert: cert.to_pem(der::pem::LineEnding::LF).unwrap().to_string() + "lalalalalalala:3:3:##:3:3;3::#:3",
            invalidated_at: None,
            not_valid_before: common::default_validity().not_before.to_unix_duration().as_secs(),
            not_valid_after: common::default_validity().not_after.to_unix_duration().as_secs(),
            cache_signature: skey.sign((serial_number.to_string() + &1234.to_string() + &5678.to_string() + "").as_bytes()).as_hex()
        };
        cacheable_cert.verify(&vkey).unwrap();
    }
}

test_all_platforms! {
    fn try_to_idcert() {
        init_logger();
        let skey = common::Ed25519PrivateKey::gen_keypair(&mut rand::rngs::OsRng);
        let vkey = skey.public_key.clone();
        let csr = common::actor_csr("skyrina", &skey);
        let cert = IdCert::from_actor_csr(csr, &skey, SerialNumber::from_bytes_be(&8u8.to_be_bytes()).unwrap(), common::home_server_subject(), common::default_validity()).unwrap();
        let serial_number =
            cert.clone().id_cert_tbs.serial_number;
        let cacheable_cert = CacheableIdCert {
            cert: cert.to_pem(der::pem::LineEnding::LF).unwrap().to_string(),
            invalidated_at: None,
            not_valid_before: common::default_validity().not_before.to_unix_duration().as_secs(),
            not_valid_after: common::default_validity().not_after.to_unix_duration().as_secs(),
            cache_signature: skey.sign((serial_number.to_string() + &common::default_validity().not_before.to_unix_duration().as_secs().to_string() + &common::default_validity().not_after.to_unix_duration().as_secs().to_string() + "").as_bytes()).as_hex() + "6789t5rygc4ghbm"
        };
        cacheable_cert.try_to_idcert(polyproto::certs::Target::Actor, common::default_validity().not_before.to_unix_duration().as_secs() + 2, &vkey).unwrap();
    }
}

test_all_platforms! {
    fn algorithm_identifier() {
        init_logger();
        let skey = common::Ed25519PrivateKey::gen_keypair(&mut rand::rngs::OsRng);
        let _vkey = skey.public_key.clone();
        let csr = common::actor_csr("skyrina", &skey);
        let cert = IdCert::from_actor_csr(csr, &skey, SerialNumber::from_bytes_be(&8u8.to_be_bytes()).unwrap(), common::home_server_subject(), common::default_validity()).unwrap();
        let serial_number =
            cert.clone().id_cert_tbs.serial_number;
        let cacheable_cert = CacheableIdCert {
            cert: cert.clone().to_pem(der::pem::LineEnding::LF).unwrap().to_string(),
            invalidated_at: None,
            not_valid_before: common::default_validity().not_before.to_unix_duration().as_secs(),
            not_valid_after: common::default_validity().not_after.to_unix_duration().as_secs(),
            cache_signature: skey.sign((serial_number.to_string() + &common::default_validity().not_before.to_unix_duration().as_secs().to_string() + &common::default_validity().not_after.to_unix_duration().as_secs().to_string() + "").as_bytes()).as_hex() + "6789t5rygc4ghbm"
        };
        assert_eq!(cert.signature.algorithm, cacheable_cert.algorithm_identifier().unwrap())
    }
}
