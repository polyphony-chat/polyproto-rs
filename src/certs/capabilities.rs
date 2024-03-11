// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use der::asn1::SetOfVec;
use der::{Any, Tag, Tagged};
use spki::ObjectIdentifier;
use x509_cert::attr::{Attribute, Attributes};

use crate::{Constrained, ConstraintError, Error};

pub const OID_KEY_USAGE_DIGITAL_SIGNATURE: &str = "1.3.6.1.5.5.7.3.3";
pub const OID_KEY_USAGE_CRL_SIGN: &str = "1.3.6.1.5.5.7.3.2";
pub const OID_KEY_USAGE_CONTENT_COMMITMENT: &str = "1.3.6.1.5.5.7.3.8";
pub const OID_KEY_USAGE_KEY_ENCIPHERMENT: &str = "1.3.6.1.5.5.7.3.1";
pub const OID_KEY_USAGE_DATA_ENCIPHERMENT: &str = "1.3.6.1.5.5.7.3.4";
pub const OID_KEY_USAGE_KEY_AGREEMENT: &str = "1.3.6.1.5.5.7.3.9";
pub const OID_KEY_USAGE_KEY_CERT_SIGN: &str = "1.3.6.1.5.5.7.3.3";
pub const OID_KEY_USAGE_ENCIPHER_ONLY: &str = "1.3.6.1.5.5.7.3.7";
pub const OID_KEY_USAGE_DECIPHER_ONLY: &str = "1.3.6.1.5.5.7.3.6";
pub const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";

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

impl Capabilities {
    /// Sane default for actor [IdCsr]/[IdCert] [Capabilities]. Uses the DigitalSignature flag,
    /// not the ContentCommitment flag.
    pub fn default_actor() -> Self {
        let key_usage = vec![KeyUsage::DigitalSignature(true)];
        let basic_constraints = BasicConstraints {
            ca: false,
            path_length: None,
        };
        Self {
            key_usage,
            basic_constraints,
        }
    }

    /// Sane default for home server [IdCsr]/[IdCert] [Capabilities].
    pub fn default_home_server() -> Self {
        let key_usage = vec![KeyUsage::KeyCertSign(true)];
        let basic_constraints = BasicConstraints {
            ca: true,
            path_length: Some(1),
        };
        Self {
            key_usage,
            basic_constraints,
        }
    }
}

impl TryFrom<Attributes> for Capabilities {
    type Error = Error;

    fn try_from(value: Attributes) -> Result<Self, Self::Error> {
        //let key_usage = Vec::new();
        //let basic_constraints;
        for item in value.iter() {
            // TODO: We have to convert an Attribute into a Capability.
            // First, we have to parse the OID of the item to determine which type of capability this
            // is. Then, we have to parse the actual Any information into a bool or number (depending)
            // on the capability type. Lastly, we can put it all together into the capabilities struct,
            // and perhaps call validate on it - although I am not sure this belongs in a try_from
            // method.
        }
        todo!()
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

impl TryFrom<Attribute> for KeyUsage {
    type Error = Error;

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
            return Err(Error::InvalidInput(crate::InvalidInput::IncompatibleVariantForConversion { reason: "This attribute does not store exactly one value, as would be expected for a KeyUsage attribute".to_string() }));
        }
        let sov = value.values.get(0);

        // The first value inside the Attribute is a SetOfVec. We need to look inside the SetOfVec to
        // find the actual attribute we are interested in.
        if let Some(inner_value) = sov {
            if inner_value.tag() != Tag::Boolean {
                return Err(Error::InvalidInput(crate::InvalidInput::IncompatibleVariantForConversion { reason: format!("Only Any objects with boolean tags can be converted to a KeyUsage enum variant. Expected Tag::Boolean, found {:?}", inner_value.tag()) }));
            }
            // This is how booleans are apparently encoded in ASN.1
            let boolean_value = match inner_value.value() {
                &[0x00] => false,
                &[0xFF] | &[0x01] => true,
                _ => {
                    return Err(Error::InvalidInput(crate::InvalidInput::IncompatibleVariantForConversion { reason: "The value of the attribute does not match the expected boolean value".to_string() }));
                }
            };
            // Now we have to match the OID of the attribute to the known KeyUsage variants
            return Ok(match value.oid.to_string().as_str() {
                OID_KEY_USAGE_CONTENT_COMMITMENT => KeyUsage::ContentCommitment(boolean_value),
                OID_KEY_USAGE_CRL_SIGN => KeyUsage::CrlSign(boolean_value),
                OID_KEY_USAGE_DATA_ENCIPHERMENT => KeyUsage::DataEncipherment(boolean_value),
                OID_KEY_USAGE_DECIPHER_ONLY => KeyUsage::DecipherOnly(boolean_value),
                OID_KEY_USAGE_DIGITAL_SIGNATURE => KeyUsage::DigitalSignature(boolean_value),
                OID_KEY_USAGE_ENCIPHER_ONLY => KeyUsage::EncipherOnly(boolean_value),
                OID_KEY_USAGE_KEY_AGREEMENT => KeyUsage::KeyAgreement(boolean_value),
                OID_KEY_USAGE_KEY_CERT_SIGN => KeyUsage::KeyCertSign(boolean_value),
                OID_KEY_USAGE_KEY_ENCIPHERMENT => KeyUsage::KeyEncipherment(boolean_value),
                // If the OID does not match any known KeyUsage variant, we return an error
                _ => {
                    return Err(Error::InvalidInput(
                        crate::InvalidInput::IncompatibleVariantForConversion {
                            reason: format!("The OID of the attribute does not match any known KeyUsage variant. Found OID \"{}\"", value.oid)
                        },
                    ))
                }
            });
        }
        // If the attribute does not contain a value, we return an error
        Err(Error::InvalidInput(
            crate::InvalidInput::IncompatibleVariantForConversion {
                reason: "The attribute does not contain a value".to_string(),
            },
        ))
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
            KeyUsage::DigitalSignature(_) => {
                ObjectIdentifier::from_str(OID_KEY_USAGE_DIGITAL_SIGNATURE)
            }
            KeyUsage::CrlSign(_) => ObjectIdentifier::from_str(OID_KEY_USAGE_CRL_SIGN),
            KeyUsage::ContentCommitment(_) => {
                ObjectIdentifier::from_str(OID_KEY_USAGE_CONTENT_COMMITMENT)
            }
            KeyUsage::KeyEncipherment(_) => {
                ObjectIdentifier::from_str(OID_KEY_USAGE_KEY_ENCIPHERMENT)
            }
            KeyUsage::DataEncipherment(_) => {
                ObjectIdentifier::from_str(OID_KEY_USAGE_DATA_ENCIPHERMENT)
            }
            KeyUsage::KeyAgreement(_) => ObjectIdentifier::from_str(OID_KEY_USAGE_KEY_AGREEMENT),
            KeyUsage::KeyCertSign(_) => ObjectIdentifier::from_str(OID_KEY_USAGE_KEY_CERT_SIGN),
            KeyUsage::EncipherOnly(_) => ObjectIdentifier::from_str(OID_KEY_USAGE_ENCIPHER_ONLY),
            KeyUsage::DecipherOnly(_) => ObjectIdentifier::from_str(OID_KEY_USAGE_DECIPHER_ONLY),
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
        ObjectIdentifier::from_str(OID_BASIC_CONSTRAINTS).expect("Error occurred when converting BasicConstraints to ObjectIdentifier. Please report this crash at https://github.com/polyphony-chat/polyproto")
    }
}

impl TryFrom<Attribute> for BasicConstraints {
    type Error = Error;
    /// Performs the conversion.
    ///
    /// Fails, if the input attribute
    /// - does not contain exactly one or two values
    /// - contains a value that is not a boolean or integer
    /// - does not have the OID of BasicConstraints
    /// - contains more than one boolean or integer value
    fn try_from(value: Attribute) -> Result<Self, Self::Error> {
        // Basic input validation. Check OID of Attribute and length of the "values" SetOfVec provided.
        if value.oid.to_string() != OID_BASIC_CONSTRAINTS {
            return Err(Error::InvalidInput(
                crate::InvalidInput::IncompatibleVariantForConversion {
                    reason: "OID of value does not match OID_BASIC_CONSTRAINTS".to_string(),
                },
            ));
        }
        let values = value.values;
        if values.len() > 2usize {
            return Err(Error::InvalidInput(
                crate::InvalidInput::IncompatibleVariantForConversion {
                    reason: format!(
                        "Expected 1 or 2 values for BasicConstraints, found {}",
                        values.len()
                    ),
                },
            ));
        }
        let mut num_ca = 0u8;
        let mut num_path_length = 0u8;
        let mut ca: bool = false;
        let mut path_length: Option<u64> = None;
        for value in values.iter() {
            match value.tag() {
                Tag::Boolean => {
                    // Keep track of how many Boolean tags we encounter
                    if num_ca == 0 {
                        num_ca += 1;
                        ca = match value.value() {
                            &[0x00] => false,
                            &[0xFF] | &[0x01] => true,
                            _ => {
                                return Err(Error::InvalidInput(
                                    crate::InvalidInput::IncompatibleVariantForConversion {
                                        reason: "Encountered unexpected value for Boolean tag".to_string(),
                                    },
                                ))
                            }
                        }
                    } else {
                        return Err(Error::InvalidInput(crate::InvalidInput::IncompatibleVariantForConversion { reason: "Encountered > 1 Boolean tags. Expected 1 Boolean tag.".to_string() }));
                    }
                }
                Tag::Integer => {
                    // Keep track of how many Integer tags we encounter
                    if num_path_length == 0 {
                        num_path_length += 1;
                        // The value is given to us a a byte slice of u8. We need to convert this
                        // into a u64.
                        let mut buf = [0u8; 8];
                        let len = 8.min(value.value().len());
                        buf[..len].copy_from_slice(value.value());
                        path_length = Some(u64::from_be_bytes(buf));
                    } else {
                        return Err(Error::InvalidInput(crate::InvalidInput::IncompatibleVariantForConversion { reason: "Encountered > 1 Integer tags. Expected 0 or 1 Integer tags.".to_string() }));
                    }
                }
                _ => return Err(Error::InvalidInput(crate::InvalidInput::IncompatibleVariantForConversion { reason: format!("Encountered unexpected tag {:?}, when tag should have been either Boolean or Integer", value.tag()) })),
            }
        }
        if num_ca == 0 {
            return Err(Error::InvalidInput(
                crate::InvalidInput::IncompatibleVariantForConversion {
                    reason: "Expected 1 Boolean tag, found 0".to_string(),
                },
            ));
        }
        Ok(BasicConstraints { ca, path_length })
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

#[cfg(test)]
mod test_key_usage_from_attribute {
    use super::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_from_attribute() {
        let key_usage = KeyUsage::ContentCommitment(true);
        let attribute = Attribute::from(key_usage);
        let result = KeyUsage::try_from(attribute);
        dbg!(&result);
        assert!(result.is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_wrong_value_amount() {
        let key_usage = KeyUsage::ContentCommitment(true);
        let mut attribute = Attribute::from(key_usage);
        attribute
            .values
            .insert(Any::from(KeyUsage::DataEncipherment(false)))
            .unwrap();
        let result = KeyUsage::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_tag_mismatch() {
        let mut sov = SetOfVec::new();
        sov.insert(Any::new(Tag::Integer, vec![0x00]).unwrap())
            .unwrap();
        let attribute = Attribute {
            oid: ObjectIdentifier::from_str(OID_KEY_USAGE_CONTENT_COMMITMENT).unwrap(),
            values: sov,
        };
        let result = KeyUsage::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_key_usage_wrong_oid() {
        let mut sov = SetOfVec::new();
        sov.insert(Any::new(Tag::Boolean, vec![0x00]).unwrap())
            .unwrap();
        let attribute = Attribute {
            oid: ObjectIdentifier::from_str("1.2.4.2.1.1.1.1.1.1.1.1.1.1.161.69").unwrap(),
            values: sov,
        };
        let result = KeyUsage::try_from(attribute);
        dbg!(&result);
        assert!(result.is_err());
    }
}

mod test_basic_constraints_from_attribute {
    use super::*;

    fn test_basic_constraints_from_attribute() {}

    fn test_basic_constraints_wrong_value_amount() {}

    fn test_basic_constraints_wrong_value_type() {}

    fn test_basic_constraints_wrong_oid() {}

    fn test_basic_constraints_from_attribute_too_many_bools_or_ints() {}

    fn test_basic_constraints_from_attribute_weird_bool_value() {}
}
