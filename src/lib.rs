// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

pub mod certificates;
pub mod keys;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum SignatureType {
    Single(SignatureAlgorithm),
    Hybrid(SignatureAlgorithm, SignatureAlgorithm),
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    ECDSA_SECP256R1_SHA256,
    ECDSA_SECP384R1_SHA384,
    ECDSA_SECP521R1_SHA512,
    #[default]
    ED25519,
    ED448,
    RSASSA_PKCS1_v_1_5_SHA256,
    RSASSA_PKCS1_v_1_5_SHA384,
    RSASSA_PKCS1_v_1_5_SHA512,
    RSASSA_PSS_SHA256,
    RSASSA_PSS_SHA384,
    RSASSA_PSS_SHA512,
    ECDSA_BRAINPOOLP256R1_SHA256,
    ECDSA_BRAINPOOLP384R1_SHA384,
    ECDSA_BRAINPOOLP512R1_SHA512,
    CRYSTALS_DILITHIUM2,
    CRYSTALS_DILITHIUM3,
    CRYSTALS_DILITHIUM5,
    CRYSTALS_DILITHIUM2_AES,
    CRYSTALS_DILITHIUM3_AES,
    CRYSTALS_DILITHIUM5_AES,
}
