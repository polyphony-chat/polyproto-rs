// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use der::asn1::{BitString, OctetString, SetOfVec};
use der::{Any, Encode, Tag, Tagged};
use spki::ObjectIdentifier;
use x509_cert::attr::Attribute;
use x509_cert::ext::Extension;

use crate::errors::base::InvalidInput;

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The key usage extension defines the purpose of the key contained in the certificate. The usage
/// restriction might be employed when a key that could be used for more than one operation is to
/// be restricted. See <https://cryptography.io/en/latest/x509/reference/#cryptography.x509.KeyUsage>
pub enum KeyUsage {
    /// This purpose is set when the subject public key is used for verifying digital
    /// signatures, other than signatures on certificates (`key_cert_sign`) and CRLs (`crl_sign`).
    DigitalSignature = 1,
    /// This purpose is set when the subject public key is used for verifying digital
    /// signatures, other than signatures on certificates (`key_cert_sign`) and CRLs (`crl_sign`).
    /// It is used to provide a non-repudiation service that protects against the signing entity
    /// falsely denying some action. In the case of later conflict, a reliable third party may
    /// determine the authenticity of the signed data. This was called `non_repudiation` in older
    /// revisions of the X.509 specification.
    ContentCommitment = 2,
    /// This purpose is set when the subject public key is used for enciphering private or
    /// secret keys.
    KeyEncipherment = 4,
    /// This purpose is set when the subject public key is used for directly enciphering raw
    /// user data without the use of an intermediate symmetric cipher.
    DataEncipherment = 8,
    /// This purpose is set when the subject public key is used for key agreement. For
    /// example, when a Diffie-Hellman key is to be used for key management, then this purpose is
    /// set.
    KeyAgreement = 16,
    /// This purpose is set when the subject public key is used for verifying signatures on
    /// public key certificates. If this purpose is set to true then ca must be true in the
    /// `BasicConstraints` extension.
    KeyCertSign = 32,
    /// This purpose is set when the subject public key is used for verifying signatures on
    /// certificate revocation lists.
    CrlSign = 64,
    /// When this purpose is set and the `key_agreement` purpose is also set, the subject
    /// public key may be used only for enciphering data while performing key agreement. The
    /// `KeyAgreement` capability must be set for this.
    EncipherOnly = 128,
    /// When this purpose is set and the `key_agreement` purpose is also set, the subject
    /// public key may be used only for deciphering data while performing key agreement. The
    /// `KeyAgreement` capability must be set for this.
    DecipherOnly = 256,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyUsages {
    pub key_usages: Vec<KeyUsage>,
}

impl KeyUsages {
    pub fn new(key_usages: &[KeyUsage]) -> Self {
        KeyUsages {
            key_usages: key_usages.to_vec(),
        }
    }
}

impl From<KeyUsages> for BitString {
    fn from(value: KeyUsages) -> Self {
        let mut number: usize = 0;
        for item in value.key_usages.iter() {
            number += *item as usize;
        }
        BitString::from_bytes(number.to_be_bytes().as_slice()).expect("Error when trying to convert KeyUsages to BitString. Please report this error to https://github.com/polyphony-chat/polyproto")
    }
}

impl TryFrom<Attribute> for KeyUsages {
    type Error = InvalidInput;

    fn try_from(value: Attribute) -> Result<Self, Self::Error> {
        if value.tag() != Tag::BitString {
            return Err(InvalidInput::IncompatibleVariantForConversion {
                reason: format!("Expected BitString, found {}", value.tag()),
            });
        }
        match value.values.len() {
            0 => return Ok(KeyUsages::new(&[])),
            1 => (),
            _ => {
                return Err(InvalidInput::ConstraintError(
                    ConstraintError::OutOfBounds {
                        lower: 0,
                        upper: 1,
                        actual: value.values.len().to_string(),
                        reason: Some("Too many values to be a valid KeyUsages value".to_string()),
                    },
                ))
            }
        };
        let inner_value = value.values.get(0).expect("Illegal state. Please report this error to https://github.com/polyphony-chat/polyproto");
    }
}

impl TryFrom<Extension> for KeyUsages {
    type Error = InvalidInput;

    fn try_from(value: Extension) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl From<KeyUsages> for Attribute {
    fn from(value: KeyUsages) -> Self {
        todo!()
    }
}

impl From<KeyUsages> for Extension {
    fn from(value: KeyUsages) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn key_usages_to_bitstring() {
        let key_usages = KeyUsages::new(&[
            KeyUsage::CrlSign,
            KeyUsage::EncipherOnly,
            KeyUsage::KeyAgreement,
        ]);
        let bitstring = BitString::from(key_usages);
        dbg!(bitstring)
    }
}
