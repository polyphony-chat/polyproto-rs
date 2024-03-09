// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use der::asn1::SetOfVec;
use der::Any;
use spki::ObjectIdentifier;
use x509_cert::attr::{Attribute, Attributes};

use crate::{Constrained, ConstraintError};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Capabilities which an ID-Cert or ID-CSR might have. For ID-Certs, you'd find these capabilities
/// in the `Extensions` field of a certificate. ID-CSRs store these capabilities as part of the
/// `Attributes` field.
///
/// This struct only covers the CertCapability subtype trees of which at least one of the subtypes
/// are relevant to polyproto certificates.
pub struct Capabilities {
    /// The key usage extension defines the purpose of the key contained in the certificate.
    pub key_usage: Vec<KeyUsage>,
    /// Extension type that defines whether a given certificate is allowed
    /// to sign additional certificates and what path length restrictions may exist.
    pub basic_constraints: BasicConstraints,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            key_usage: Default::default(),
            basic_constraints: BasicConstraints {
                ca: false,
                path_length: None,
            },
        }
    }
}

impl TryFrom<Capabilities> for Attributes {
    /// Performs the conversion.
    ///
    /// Fails, if `Capabilities::verify()` using the `Constrained` trait fails.
    fn try_from(value: Capabilities) -> Result<Self, Self::Error> {
        value.validate()?;
        let mut sov = SetOfVec::new();
        for item in value.key_usage.iter() {
            let insertion = sov.insert(Attribute::from(*item));
            if insertion.is_err() {
                return Err(ConstraintError::Malformed(Some("Tried inserting non-unique element into SetOfVec. You likely have a duplicate value in your Capabilities".to_string())));
            }
        }
        let insertion = sov.insert(Attribute::from(value.basic_constraints));
        if insertion.is_err() {
            return Err(ConstraintError::Malformed(Some("Tried inserting non-unique element into SetOfVec. You likely have a duplicate value in your Capabilities".to_string())));
        }
        Ok(sov)
    }

    type Error = ConstraintError;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The key usage extension defines the purpose of the key contained in the certificate. The usage
/// restriction might be employed when a key that could be used for more than one operation is to
/// be restricted. See <https://cryptography.io/en/latest/x509/reference/#cryptography.x509.KeyUsage>
pub enum KeyUsage {
    /// This purpose is set to true when the subject public key is used for verifying digital
    /// signatures, other than signatures on certificates (`key_cert_sign`) and CRLs (`crl_sign`).
    DigitalSignature(bool),
    /// This purpose is set to true when the subject public key is used for verifying signatures on
    /// certificate revocation lists.
    CrlSign(bool),
    /// This purpose is set to true when the subject public key is used for verifying digital
    /// signatures, other than signatures on certificates (`key_cert_sign`) and CRLs (`crl_sign`).
    /// It is used to provide a non-repudiation service that protects against the signing entity
    /// falsely denying some action. In the case of later conflict, a reliable third party may
    /// determine the authenticity of the signed data. This was called `non_repudiation` in older
    /// revisions of the X.509 specification.
    ContentCommitment(bool),
    /// This purpose is set to true when the subject public key is used for enciphering private or
    /// secret keys.
    KeyEncipherment(bool),
    /// This purpose is set to true when the subject public key is used for directly enciphering raw
    /// user data without the use of an intermediate symmetric cipher.
    DataEncipherment(bool),
    /// This purpose is set to true when the subject public key is used for key agreement. For
    /// example, when a Diffie-Hellman key is to be used for key management, then this purpose is
    /// set to true.
    KeyAgreement(bool),
    /// This purpose is set to true when the subject public key is used for verifying signatures on
    /// public key certificates. If this purpose is set to true then ca must be true in the
    /// `BasicConstraints` extension.
    KeyCertSign(bool),
    /// When this purposes is set to true and the `key_agreement` purpose is also set, the subject
    /// public key may be used only for enciphering data while performing key agreement. The
    /// `KeyAgreement` capability must be set to `true` for this.
    EncipherOnly(bool),
    /// When this purposes is set to true and the `key_agreement` purpose is also set, the subject
    /// public key may be used only for deciphering data while performing key agreement. The
    /// `KeyAgreement` capability must be set to `true` for this.
    DecipherOnly(bool),
}

impl From<KeyUsage> for bool {
    fn from(value: KeyUsage) -> Self {
        match value {
            KeyUsage::DigitalSignature(val) => val,
            KeyUsage::CrlSign(val) => val,
            KeyUsage::ContentCommitment(val) => val,
            KeyUsage::KeyEncipherment(val) => val,
            KeyUsage::DataEncipherment(val) => val,
            KeyUsage::KeyAgreement(val) => val,
            KeyUsage::KeyCertSign(val) => val,
            KeyUsage::EncipherOnly(val) => val,
            KeyUsage::DecipherOnly(val) => val,
        }
    }
}

impl From<KeyUsage> for Any {
    fn from(value: KeyUsage) -> Self {
        Any::new(der::Tag::Boolean,match bool::from(value) {
            true => vec![0xff],
            false => vec![0x00],
        },
        ).expect("Error occurred when converting BasicConstraints bool to der::Any. Please report this crash at https://github.com/polyphony-chat/polyproto.")
    }
}

impl From<KeyUsage> for ObjectIdentifier {
    fn from(value: KeyUsage) -> Self {
        let result = match value {
            KeyUsage::DigitalSignature(_) => ObjectIdentifier::from_str("1.3.6.1.5.5.7.3.3"),
            KeyUsage::CrlSign(_) => ObjectIdentifier::from_str("1.3.6.1.5.5.7.3.2"),
            KeyUsage::ContentCommitment(_) => ObjectIdentifier::from_str("1.3.6.1.5.5.7.3.8"),
            KeyUsage::KeyEncipherment(_) => ObjectIdentifier::from_str("1.3.6.1.5.5.7.3.1"),
            KeyUsage::DataEncipherment(_) => ObjectIdentifier::from_str("1.3.6.1.5.5.7.3.4"),
            KeyUsage::KeyAgreement(_) => ObjectIdentifier::from_str("1.3.6.1.5.5.7.3.9"),
            KeyUsage::KeyCertSign(_) => ObjectIdentifier::from_str("1.3.6.1.5.5.7.3.3"),
            KeyUsage::EncipherOnly(_) => ObjectIdentifier::from_str("1.3.6.1.5.5.7.3.7"),
            KeyUsage::DecipherOnly(_) => ObjectIdentifier::from_str("1.3.6.1.5.5.7.3.6"),
        };
        result.expect("Error occurred when converting KeyUsage enum to ObjectIdentifier. Please report this crash at https://github.com/polyphony-chat/polyproto.")
    }
}

impl From<KeyUsage> for Attribute {
    fn from(value: KeyUsage) -> Self {
        // Creating a Any from a bool is really simple, so we can expect this to never fail.
        let any_val = Any::from(value);
        let mut sov = SetOfVec::new();
        // .insert() only fails if the value is not unique. We are inserting a single value, so this
        // should never fail. See tests below for verification.
        sov.insert(any_val).expect("Error occurred when inserting KeyUsage into der::Any to SetOfVec. Please report this crash at https://github.com/polyphony-chat/polyproto");
        Attribute {
            oid: value.into(),
            values: sov,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Basic constraints is an X.509 extension type that defines whether a given certificate is allowed
/// to sign additional certificates and what path length restrictions may exist.
pub struct BasicConstraints {
    /// Whether the certificate can sign certificates.
    pub ca: bool,
    /// The maximum path length for certificates subordinate to this certificate. This attribute
    /// only has meaning if `ca` is true. If `ca` is true then a path length of None means there’s no
    /// restriction on the number of subordinate CAs in the certificate chain. If it is zero or
    /// greater then it defines the maximum length for a subordinate CA’s certificate chain. For
    /// example, a `path_length` of 1 means the certificate can sign a subordinate CA, but the
    /// subordinate CA is not allowed to create subordinates with `ca` set to true.
    pub path_length: Option<u64>,
}

impl From<BasicConstraints> for ObjectIdentifier {
    fn from(_value: BasicConstraints) -> Self {
        ObjectIdentifier::from_str("2.5.29.19").expect("Error occurred when converting BasicConstraints to ObjectIdentifier. Please report this crash at https://github.com/polyphony-chat/polyproto")
    }
}

impl From<BasicConstraints> for Attribute {
    fn from(value: BasicConstraints) -> Self {
        let mut sov = SetOfVec::new();
        sov.insert(Any::new(der::Tag::Boolean, match value.ca {
                        true => vec![0xff],
                        false => vec![0x00],
                    },
                ).expect("Error occurred when converting BasicConstraints bool to der::Any. Please report this crash at https://github.com/polyphony-chat/polyproto.")).expect("Error occurred when inserting into der::Any to SetOfVec. Please report this crash at https://github.com/polyphony-chat/polyproto");
        if let Some(length) = value.path_length {
            sov.insert(Any::new(der::Tag::Integer, length.to_be_bytes()).expect("Error occurred when converting BasicConstraints u64 to der::Any. Please report this crash at https://github.com/polyphony-chat/polyproto.")).
            expect("Error occurred when inserting into der::Any to SetOfVec. Please report this crash at https://github.com/polyphony-chat/polyproto");
        }
        Attribute {
            oid: value.into(),
            values: sov,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_to_object_identifier() {
        let _ = ObjectIdentifier::from(KeyUsage::DigitalSignature(true));
        let _ = ObjectIdentifier::from(KeyUsage::CrlSign(true));
        let _ = ObjectIdentifier::from(KeyUsage::ContentCommitment(true));
        let _ = ObjectIdentifier::from(KeyUsage::KeyEncipherment(true));
        let _ = ObjectIdentifier::from(KeyUsage::DataEncipherment(true));
        let _ = ObjectIdentifier::from(KeyUsage::KeyAgreement(true));
        let _ = ObjectIdentifier::from(KeyUsage::KeyCertSign(true));
        let _ = ObjectIdentifier::from(KeyUsage::EncipherOnly(true));
        let _ = ObjectIdentifier::from(KeyUsage::DecipherOnly(true));
    }

    fn test_key_usage_to_attribute(val: bool) {
        let _ = Attribute::from(KeyUsage::DigitalSignature(val));
        let _ = Attribute::from(KeyUsage::CrlSign(val));
        let _ = Attribute::from(KeyUsage::ContentCommitment(val));
        let _ = Attribute::from(KeyUsage::KeyEncipherment(val));
        let _ = Attribute::from(KeyUsage::DataEncipherment(val));
        let _ = Attribute::from(KeyUsage::KeyAgreement(val));
        let _ = Attribute::from(KeyUsage::KeyCertSign(val));
        let _ = Attribute::from(KeyUsage::EncipherOnly(val));
        let _ = Attribute::from(KeyUsage::DecipherOnly(val));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_to_attribute_true() {
        test_key_usage_to_attribute(true);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_to_attribute_false() {
        test_key_usage_to_attribute(false);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_basic_constraints_to_object_identifier() {
        let bc = BasicConstraints {
            ca: true,
            path_length: None,
        };
        let _ = ObjectIdentifier::from(bc);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_basic_constraints_to_attribute() {
        let mut bc = BasicConstraints {
            ca: false,
            path_length: None,
        };
        let _ = Attribute::from(bc);

        bc.ca = true;
        let _ = Attribute::from(bc);

        bc.path_length = Some(0);
        let _ = Attribute::from(bc);

        // Why not test all sorts of values? :3
        let mut county_count = 2u64;
        while county_count != u64::MAX {
            dbg!(county_count);
            bc.path_length = Some(county_count);
            let _ = Attribute::from(bc);
            if let Some(res) = county_count.checked_mul(2) {
                county_count = res;
            } else {
                county_count = u64::MAX;
            }
        }
    }
}
