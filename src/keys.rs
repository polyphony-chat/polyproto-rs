// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::{HasSignatureType, SignatureType};

/// A cryptographic key struct, containing a key string and metadata about the key's type.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Key {
    pub key: String,
    pub signature_type: SignatureType,
}

impl Key {
    /// Converts the key to a byte vector. The byte vector is formatted as follows:
    /// - The length of the key in bytes as a big-endian 32-bit integer
    /// - The key itself, as a sequence of bytes. Valid UTF-8.
    /// - A single byte representing the signature type:
    ///     - `0x00` for a single signature type
    ///     - `0x01` for a hybrid (dual) signature type
    /// - If the signature type is single, a single byte representing the signature algorithm
    /// - If the signature type is hybrid, two bytes representing the signature algorithms
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.key.len().to_be_bytes());
        bytes.extend_from_slice(self.key.as_bytes());
        match self.signature_type {
            SignatureType::Single(alg) => {
                // 00000000 xxxxxxxx
                bytes.push(0);
                bytes.push(alg as u8);
            }
            SignatureType::Hybrid(alg1, alg2) => {
                // 00000001 xxxxxxxx xxxxxxxx
                bytes.push(1);
                bytes.push(alg1 as u8);
                bytes.push(alg2 as u8);
            }
        }
        bytes
    }
}

impl HasSignatureType for Key {
    fn signature_type(&self) -> SignatureType {
        self.signature_type
    }
}
