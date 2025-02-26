// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use polyproto::api::core::cacheable_cert::CacheableIdCert;
use polyproto::key::{PrivateKey, PublicKey};
use polyproto::signature::Signature;
use polyproto::types::der::asn1::Uint;

use crate::common::{self, Ed25519Signature};

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
                (u64::try_from(Uint(some_cert.id_cert_tbs.serial_number.clone()))
                    .unwrap()
                    .to_string()
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
            (u64::try_from(Uint(some_cert.id_cert_tbs.serial_number))
                .unwrap()
                .to_string()
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
