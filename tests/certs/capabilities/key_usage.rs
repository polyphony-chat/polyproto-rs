// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use der::asn1::BitString;
use log::trace;
use polyproto::certs::capabilities::{KeyUsage, KeyUsages};

use crate::common::init_logger;

#[test]
fn to_bitstring() {
    init_logger();
    let key_usages_vec = vec![
        KeyUsage::DigitalSignature,
        KeyUsage::ContentCommitment,
        KeyUsage::KeyEncipherment,
        KeyUsage::DataEncipherment,
        KeyUsage::KeyAgreement,
        KeyUsage::KeyCertSign,
        KeyUsage::CrlSign,
        KeyUsage::EncipherOnly,
        KeyUsage::DecipherOnly,
    ];
    let key_usages = KeyUsages {
        key_usages: key_usages_vec,
    };
    let bitstring = key_usages.to_bitstring();
    trace!("Unused bits: {}", bitstring.unused_bits());
    assert_eq!(bitstring.raw_bytes(), &[128, 255]);

    let key_usages_vec = vec![KeyUsage::DecipherOnly];
    let key_usages = KeyUsages {
        key_usages: key_usages_vec,
    };
    let bitstring = key_usages.to_bitstring();
    trace!("Unused bits: {}", bitstring.unused_bits());
    assert_eq!(bitstring.raw_bytes(), &[128, 0]);

    let key_usages_vec = vec![KeyUsage::DigitalSignature];
    let key_usages = KeyUsages {
        key_usages: key_usages_vec,
    };
    let bitstring = key_usages.to_bitstring();
    trace!("Unused bits: {}", bitstring.unused_bits());
    assert_eq!(bitstring.raw_bytes(), &[128]);

    let key_usages_vec = vec![
        KeyUsage::DigitalSignature,
        KeyUsage::ContentCommitment,
        KeyUsage::KeyEncipherment,
        KeyUsage::DataEncipherment,
        KeyUsage::KeyAgreement,
        KeyUsage::KeyCertSign,
        KeyUsage::CrlSign,
        KeyUsage::EncipherOnly,
    ];
    let key_usages = KeyUsages {
        key_usages: key_usages_vec,
    };
    let bitstring = key_usages.to_bitstring();
    trace!("Unused bits: {}", bitstring.unused_bits());
    assert_eq!(bitstring.raw_bytes(), &[255]);
}

#[test]
fn from_bitstring() {
    let bitstring = BitString::new(7, [128, 255]).unwrap();
    let key_usages = KeyUsages::from_bitstring(bitstring).unwrap();
    assert_eq!(
        key_usages.key_usages,
        vec![
            KeyUsage::DigitalSignature,
            KeyUsage::ContentCommitment,
            KeyUsage::KeyEncipherment,
            KeyUsage::DataEncipherment,
            KeyUsage::KeyAgreement,
            KeyUsage::KeyCertSign,
            KeyUsage::CrlSign,
            KeyUsage::EncipherOnly,
            KeyUsage::DecipherOnly
        ]
    );
}
