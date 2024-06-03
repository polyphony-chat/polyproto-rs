// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(feature = "serde")]
use {
    crate::types::serde_compat::{
        der::asn1::Ia5String, spki::AlgorithmIdentifierOwned,
        spki::SubjectPublicKeyInfo as SubjectPublicKeyInfoOwned,
    },
    ::serde::Deserialize,
    ::serde::Serialize,
};

#[cfg(not(feature = "serde"))]
use {
    crate::types::LikeSubjectPublicKeyInfo,
    der::asn1::Ia5String,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
};

use der::asn1::BitString;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
        #[allow(clippy::useless_conversion)]
        PrivateKeyInfo {
            algorithm: value.algorithm.clone().into(),
            encrypted_private_key_bitstring: value.subject_public_key.clone(),
        }
    }
}

impl From<PrivateKeyInfo> for SubjectPublicKeyInfoOwned {
    fn from(value: PrivateKeyInfo) -> Self {
        SubjectPublicKeyInfoOwned::new(value.algorithm, value.encrypted_private_key_bitstring)
    }
}

#[cfg(feature = "serde")]
mod serde {
    use der::pem::LineEnding;
    use serde::de::Visitor;
    use serde::{Deserialize, Serialize};

    use crate::types::serde_compat::spki::SubjectPublicKeyInfo;

    struct PrivateKeyInfoVisitor;

    impl<'de> Visitor<'de> for PrivateKeyInfoVisitor {
        type Value = crate::types::encrypted_pkm::PrivateKeyInfo;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a private key info structure, which is a subject public key info structure as defined in RFC 5280. this private key info structure needs to be a valid PEM encoded ASN.1 structure")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            crate::types::serde_compat::spki::SubjectPublicKeyInfo::from_pem(v.as_bytes())
                .map_err(serde::de::Error::custom)
                .map(Into::into)
        }
    }

    impl<'de> Deserialize<'de> for crate::types::encrypted_pkm::PrivateKeyInfo {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_str(PrivateKeyInfoVisitor)
        }
    }

    impl Serialize for crate::types::encrypted_pkm::PrivateKeyInfo {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(
                SubjectPublicKeyInfo::from(self.clone())
                    .to_pem(LineEnding::LF)
                    .map_err(serde::ser::Error::custom)?
                    .as_str(),
            )
        }
    }
}
