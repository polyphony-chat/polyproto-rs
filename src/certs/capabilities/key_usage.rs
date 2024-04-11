// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use der::asn1::SetOfVec;
use der::{Any, Tag, Tagged};
use spki::ObjectIdentifier;
use x509_cert::attr::Attribute;

use crate::errors::base::InvalidInput;

// TODO: Replace usages of KeyUsageFlag with KeyUsage

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyUsage {
    pub oid: ObjectIdentifier,
    pub flag: KeyUsageFlag,
    pub critical: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The key usage extension defines the purpose of the key contained in the certificate. The usage
/// restriction might be employed when a key that could be used for more than one operation is to
/// be restricted. See <https://cryptography.io/en/latest/x509/reference/#cryptography.x509.KeyUsage>
pub enum KeyUsageFlag {
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

impl From<KeyUsageFlag> for bool {
    fn from(value: KeyUsageFlag) -> Self {
        match value {
            KeyUsageFlag::DigitalSignature(val) => val,
            KeyUsageFlag::CrlSign(val) => val,
            KeyUsageFlag::ContentCommitment(val) => val,
            KeyUsageFlag::KeyEncipherment(val) => val,
            KeyUsageFlag::DataEncipherment(val) => val,
            KeyUsageFlag::KeyAgreement(val) => val,
            KeyUsageFlag::KeyCertSign(val) => val,
            KeyUsageFlag::EncipherOnly(val) => val,
            KeyUsageFlag::DecipherOnly(val) => val,
        }
    }
}

impl TryFrom<Attribute> for KeyUsageFlag {
    type Error = InvalidInput;

    /// Performs the conversion.
    ///
    /// Fails, if the input attribute does not contain exactly one value, or if the input attribute
    /// does not contain a boolean value. Also fails if the OID of the attribute does not match any
    /// known KeyUsage variant.
    fn try_from(value: Attribute) -> Result<Self, Self::Error> {
        // PRETTYFYME: I know this is a bit of a mess, but it works. If anyone wants to make it
        // prettier, feel free to do so.

        // Check if the attribute contains exactly one value
        if value.values.len() != 1usize {
            return Err(InvalidInput::IncompatibleVariantForConversion { reason: "This attribute does not store exactly one value, as would be expected for a KeyUsage attribute".to_string() });
        }
        let sov = value.values.get(0);

        // The first value inside the Attribute is a SetOfVec. We need to look inside the SetOfVec to
        // find the actual attribute we are interested in.
        if let Some(inner_value) = sov {
            if inner_value.tag() != Tag::Boolean {
                return Err(InvalidInput::IncompatibleVariantForConversion { reason: format!("Only Any objects with boolean tags can be converted to a KeyUsage enum variant. Expected Tag::Boolean, found {:?}", inner_value.tag()) });
            }
            // This is how booleans are apparently encoded in ASN.1
            let boolean_value = match inner_value.value() {
                &[0x00] => false,
                &[0xFF] | &[0x01] => true,
                _ => {
                    return Err(InvalidInput::IncompatibleVariantForConversion {
                        reason: "Encountered unexpected value for Boolean tag".to_string(),
                    });
                }
            };
            // Now we have to match the OID of the attribute to the known KeyUsage variants
            return Ok(match value.oid.to_string().as_str() {
                super::OID_KEY_USAGE_CONTENT_COMMITMENT => KeyUsageFlag::ContentCommitment(boolean_value),
                super::OID_KEY_USAGE_CRL_SIGN => KeyUsageFlag::CrlSign(boolean_value),
                super::OID_KEY_USAGE_DATA_ENCIPHERMENT => KeyUsageFlag::DataEncipherment(boolean_value),
                super::OID_KEY_USAGE_DECIPHER_ONLY => KeyUsageFlag::DecipherOnly(boolean_value),
                super::OID_KEY_USAGE_DIGITAL_SIGNATURE => KeyUsageFlag::DigitalSignature(boolean_value),
                super::OID_KEY_USAGE_ENCIPHER_ONLY => KeyUsageFlag::EncipherOnly(boolean_value),
                super::OID_KEY_USAGE_KEY_AGREEMENT => KeyUsageFlag::KeyAgreement(boolean_value),
                #[allow(unreachable_patterns)] // cargo thinks the below pattern is unreachable.
                super::OID_KEY_USAGE_KEY_CERT_SIGN => KeyUsageFlag::KeyCertSign(boolean_value),
                super::OID_KEY_USAGE_KEY_ENCIPHERMENT => KeyUsageFlag::KeyEncipherment(boolean_value),
                // If the OID does not match any known KeyUsage variant, we return an error
                _ => {
                    return Err(InvalidInput::IncompatibleVariantForConversion {
                            reason: format!("The OID of the attribute does not match any known KeyUsage variant. Found OID \"{}\"", value.oid)
                        },
                    )
                }
            });
        }
        // If the attribute does not contain a value, we return an error
        Err(InvalidInput::IncompatibleVariantForConversion {
            reason: "The attribute does not contain a value".to_string(),
        })
    }
}

impl From<KeyUsageFlag> for Any {
    fn from(value: KeyUsageFlag) -> Self {
        Any::new(der::Tag::Boolean,match bool::from(value) {
            true => vec![0xff],
            false => vec![0x00],
        },
        ).expect("Error occurred when converting BasicConstraints bool to der::Any. Please report this crash at https://github.com/polyphony-chat/polyproto.")
    }
}

// TODO: This should be deleted -> move into `KeyUsage`
impl From<KeyUsageFlag> for ObjectIdentifier {
    fn from(value: KeyUsageFlag) -> Self {
        let result = match value {
            KeyUsageFlag::DigitalSignature(_) => {
                ObjectIdentifier::from_str(super::OID_KEY_USAGE_DIGITAL_SIGNATURE)
            }
            KeyUsageFlag::CrlSign(_) => ObjectIdentifier::from_str(super::OID_KEY_USAGE_CRL_SIGN),
            KeyUsageFlag::ContentCommitment(_) => {
                ObjectIdentifier::from_str(super::OID_KEY_USAGE_CONTENT_COMMITMENT)
            }
            KeyUsageFlag::KeyEncipherment(_) => {
                ObjectIdentifier::from_str(super::OID_KEY_USAGE_KEY_ENCIPHERMENT)
            }
            KeyUsageFlag::DataEncipherment(_) => {
                ObjectIdentifier::from_str(super::OID_KEY_USAGE_DATA_ENCIPHERMENT)
            }
            KeyUsageFlag::KeyAgreement(_) => {
                ObjectIdentifier::from_str(super::OID_KEY_USAGE_KEY_AGREEMENT)
            }
            KeyUsageFlag::KeyCertSign(_) => {
                ObjectIdentifier::from_str(super::OID_KEY_USAGE_KEY_CERT_SIGN)
            }
            KeyUsageFlag::EncipherOnly(_) => {
                ObjectIdentifier::from_str(super::OID_KEY_USAGE_ENCIPHER_ONLY)
            }
            KeyUsageFlag::DecipherOnly(_) => {
                ObjectIdentifier::from_str(super::OID_KEY_USAGE_DECIPHER_ONLY)
            }
        };
        result.expect("Error occurred when converting KeyUsage enum to ObjectIdentifier. Please report this crash at https://github.com/polyphony-chat/polyproto.")
    }
}

impl From<KeyUsageFlag> for Attribute {
    fn from(value: KeyUsageFlag) -> Self {
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
