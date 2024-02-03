// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use signature::Keypair;

use crate::{HasSignatureType, SignatureType};

/// Represents a private key, its corresponding public key and by extension, its signature type.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct PrivateKey {
    pub private_key: String,
    signature_type: SignatureType,
    pub public_key: PublicKey,
}

impl HasSignatureType for PrivateKey {
    fn signature_type(&self) -> SignatureType {
        self.signature_type
    }
}

/// Represents a public key and its corresponding signature type.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct PublicKey {
    pub public_key: String,
    signature_type: SignatureType,
}

impl HasSignatureType for PublicKey {
    fn signature_type(&self) -> SignatureType {
        self.signature_type
    }
}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }
}

impl Keypair for PrivateKey {
    type VerifyingKey = PublicKey;

    fn verifying_key(&self) -> PublicKey {
        self.public_key.clone()
    }
}
