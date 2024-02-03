// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

pub mod certificates;
pub mod error;
pub mod keys;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum SignatureType {
    Single(SignatureAlgorithm),
    Hybrid(SignatureAlgorithm, SignatureAlgorithm),
}

pub trait HasSignatureType {
    fn signature_type(&self) -> SignatureType;
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

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureAlgorithm::ECDSA_SECP256R1_SHA256 => write!(f, "ECDSA_SECP256R1_SHA256"),
            SignatureAlgorithm::ECDSA_SECP384R1_SHA384 => write!(f, "ECDSA_SECP384R1_SHA384"),
            SignatureAlgorithm::ECDSA_SECP521R1_SHA512 => write!(f, "ECDSA_SECP521R1_SHA512"),
            SignatureAlgorithm::ED25519 => write!(f, "ED25519"),
            SignatureAlgorithm::ED448 => write!(f, "ED448"),
            SignatureAlgorithm::RSASSA_PKCS1_v_1_5_SHA256 => write!(f, "RSASSA_PKCS1_v_1_5_SHA256"),
            SignatureAlgorithm::RSASSA_PKCS1_v_1_5_SHA384 => write!(f, "RSASSA_PKCS1_v_1_5_SHA384"),
            SignatureAlgorithm::RSASSA_PKCS1_v_1_5_SHA512 => write!(f, "RSASSA_PKCS1_v_1_5_SHA512"),
            SignatureAlgorithm::RSASSA_PSS_SHA256 => write!(f, "RSASSA_PSS_SHA256"),
            SignatureAlgorithm::RSASSA_PSS_SHA384 => write!(f, "RSASSA_PSS_SHA384"),
            SignatureAlgorithm::RSASSA_PSS_SHA512 => write!(f, "RSASSA_PSS_SHA512"),
            SignatureAlgorithm::ECDSA_BRAINPOOLP256R1_SHA256 => {
                write!(f, "ECDSA_BRAINPOOLP256R1_SHA256")
            }
            SignatureAlgorithm::ECDSA_BRAINPOOLP384R1_SHA384 => {
                write!(f, "ECDSA_BRAINPOOLP384R1_SHA384")
            }
            SignatureAlgorithm::ECDSA_BRAINPOOLP512R1_SHA512 => {
                write!(f, "ECDSA_BRAINPOOLP512R1_SHA512")
            }
            SignatureAlgorithm::CRYSTALS_DILITHIUM2 => write!(f, "CRYSTALS_DILITHIUM2"),
            SignatureAlgorithm::CRYSTALS_DILITHIUM3 => write!(f, "CRYSTALS_DILITHIUM3"),
            SignatureAlgorithm::CRYSTALS_DILITHIUM5 => write!(f, "CRYSTALS_DILITHIUM5"),
            SignatureAlgorithm::CRYSTALS_DILITHIUM2_AES => write!(f, "CRYSTALS_DILITHIUM2_AES"),
            SignatureAlgorithm::CRYSTALS_DILITHIUM3_AES => write!(f, "CRYSTALS_DILITHIUM3_AES"),
            SignatureAlgorithm::CRYSTALS_DILITHIUM5_AES => write!(f, "CRYSTALS_DILITHIUM5_AES"),
        }
    }
}
