// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use signature::Keypair;

use crate::SignatureType;

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct PrivateKey {
    pub private_key: String,
    pub public_key: PublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct PublicKey {
    pub public_key: String,
    pub signature_type_type: SignatureType,
}

impl Keypair for PrivateKey {
    type VerifyingKey = PublicKey;

    fn verifying_key(&self) -> PublicKey {
        self.public_key.clone()
    }
}
