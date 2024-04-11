// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use der::asn1::SetOfVec;
use der::{Any, Tag, Tagged};
use spki::ObjectIdentifier;
use x509_cert::attr::Attribute;

use crate::errors::base::InvalidInput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
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
        ObjectIdentifier::from_str(super::OID_BASIC_CONSTRAINTS).expect("Error occurred when converting BasicConstraints to ObjectIdentifier. Please report this crash at https://github.com/polyphony-chat/polyproto")
    }
}

impl TryFrom<Attribute> for BasicConstraints {
    type Error = InvalidInput;
    /// Performs the conversion.
    ///
    /// Fails, if the input attribute
    /// - does not contain exactly one or two values
    /// - contains a value that is not a boolean or integer
    /// - does not have the OID of BasicConstraints
    /// - contains more than one boolean or integer value
    fn try_from(value: Attribute) -> Result<Self, Self::Error> {
        // Basic input validation. Check OID of Attribute and length of the "values" SetOfVec provided.
        if value.oid.to_string() != super::OID_BASIC_CONSTRAINTS {
            return Err(Self::Error::IncompatibleVariantForConversion {
                reason: format!(
                    "OID of value does not match any of OID_BASIC_CONSTRAINTS. Found OID {}",
                    value.oid
                ),
            });
        }
        let values = value.values;
        if values.len() > 2usize {
            return Err(InvalidInput::IncompatibleVariantForConversion {
                reason: format!(
                    "Expected 1 or 2 values for BasicConstraints, found {}",
                    values.len()
                ),
            });
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
                                return Err(
                                    InvalidInput::IncompatibleVariantForConversion {
                                        reason: "Encountered unexpected value for Boolean tag".to_string(),
                                    },
                                )
                            }
                        }
                    } else {
                        return Err(InvalidInput::IncompatibleVariantForConversion { reason: "Encountered > 1 Boolean tags. Expected 1 Boolean tag.".to_string() });
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
                        return Err(InvalidInput::IncompatibleVariantForConversion { reason: "Encountered > 1 Integer tags. Expected 0 or 1 Integer tags.".to_string() });
                    }
                }
                _ => return Err(InvalidInput::IncompatibleVariantForConversion { reason: format!("Encountered unexpected tag {:?}, when tag should have been either Boolean or Integer", value.tag()) }),
            }
        }
        if num_ca == 0 {
            return Err(InvalidInput::IncompatibleVariantForConversion {
                reason: "Expected 1 Boolean tag, found 0".to_string(),
            });
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
