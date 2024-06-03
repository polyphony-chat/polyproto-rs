// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(feature = "serde")]
use crate::types::serde::{
    der::asn1::Ia5String, spki::SubjectPublicKeyInfo as SubjectPublicKeyInfoOwned,
};

#[cfg(not(feature = "serde"))]
use {
    super::serde::spki::LikeSubjectPublicKeyInfo, der::asn1::Ia5String,
    spki::SubjectPublicKeyInfoOwned,
};

use der::asn1::BitString;
use spki::AlgorithmIdentifierOwned;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A private key material structure for storing encrypted private key material on a home server.
pub struct EncryptedPkm {
    pub serial_number: Ia5String,
    pub key_data: PrivateKeyInfo,
    pub encryption_algorithm: AlgorithmIdentifierOwned,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// Private key material with additional information about the private keys' algorithm.
pub struct PrivateKeyInfo {
    pub algorithm: AlgorithmIdentifierOwned,
    pub encrypted_private_key_bitstring: BitString,
}

impl From<SubjectPublicKeyInfoOwned> for PrivateKeyInfo {
    fn from(value: SubjectPublicKeyInfoOwned) -> Self {
        PrivateKeyInfo {
            algorithm: value.algorithm.clone(),
            encrypted_private_key_bitstring: value.subject_public_key.clone(),
        }
    }
}

impl From<PrivateKeyInfo> for SubjectPublicKeyInfoOwned {
    fn from(value: PrivateKeyInfo) -> Self {
        SubjectPublicKeyInfoOwned::new(value.algorithm, value.encrypted_private_key_bitstring)
    }
}
