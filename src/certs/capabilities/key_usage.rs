// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use der::asn1::{BitString, OctetString, SetOfVec};
use der::{Any, Decode, Encode, Tag, Tagged};
use spki::ObjectIdentifier;
use x509_cert::attr::Attribute;
use x509_cert::ext::Extension;

use crate::errors::base::InvalidInput;
use crate::errors::composite::ConversionError;

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

impl TryFrom<u32> for KeyUsage {
    type Error = ConversionError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > 256 {
            return Err(ConversionError::InvalidInput(InvalidInput::Length {
                min_length: 0,
                max_length: 256,
                actual_length: value.to_string(),
            }));
        }
        match value {
            x if x == KeyUsage::DigitalSignature as u32 => Ok(KeyUsage::DigitalSignature),
            x if x == KeyUsage::ContentCommitment as u32 => Ok(KeyUsage::ContentCommitment),
            x if x == KeyUsage::KeyEncipherment as u32 => Ok(KeyUsage::KeyEncipherment),
            x if x == KeyUsage::DataEncipherment as u32 => Ok(KeyUsage::DataEncipherment),
            x if x == KeyUsage::KeyAgreement as u32 => Ok(KeyUsage::KeyAgreement),
            x if x == KeyUsage::KeyCertSign as u32 => Ok(KeyUsage::KeyCertSign),
            x if x == KeyUsage::CrlSign as u32 => Ok(KeyUsage::CrlSign),
            x if x == KeyUsage::EncipherOnly as u32 => Ok(KeyUsage::EncipherOnly),
            x if x == KeyUsage::DecipherOnly as u32 => Ok(KeyUsage::DecipherOnly),
            _ => Err(ConversionError::InvalidInput(InvalidInput::Malformed(
                "Input cannot be matched to any of the KeyUsage variants".to_string(),
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
/// The KeyUsages struct is a collection of KeyUsage variants.
pub struct KeyUsages {
    /// Vector of KeyUsage variants.
    pub key_usages: Vec<KeyUsage>,
}

impl KeyUsages {
    /// Creates a new KeyUsages struct from a slice of KeyUsage variants.
    pub fn new(key_usages: &[KeyUsage]) -> Self {
        KeyUsages {
            key_usages: key_usages.to_vec(),
        }
    }

    /// Converts a byte slice to a KeyUsages struct, given that the byte slice is a bitstring
    /// representing the KeyUsages.
    ///
    /// RFC 5280 says:
    /// ```text
    /// KeyUsage ::= BIT STRING {
    ///     digitalSignature        (0),
    ///     nonRepudiation          (1), -- recent editions of X.509 have
    ///                                  -- renamed this bit to contentCommitment
    ///     keyEncipherment         (2),
    ///     dataEncipherment        (3),
    ///     keyAgreement            (4),
    ///     keyCertSign             (5),
    ///     cRLSign                 (6),
    ///     encipherOnly            (7),
    ///     decipherOnly            (8) }
    /// ```
    pub fn from_bitstring(bitstring: BitString) -> Result<Self, ConversionError> {
        /* Below, we are doing some operations on bits. RFC 5280 says:
        KeyUsage ::= BIT STRING {
            digitalSignature        (0),
            nonRepudiation          (1), -- recent editions of X.509 have
                                -- renamed this bit to contentCommitment
            keyEncipherment         (2),
            dataEncipherment        (3),
            keyAgreement            (4),
            keyCertSign             (5),
            cRLSign                 (6),
            encipherOnly            (7),
            decipherOnly            (8) }

        It is now our task to check, which bits (0 - 8) are set, and to construct KeyUsage variants
        from this information.
        Note, that BitStrings represent the bits they store in big endian order, meaning that the
        most significant bit (MSB) is the first bit in the BitString.
        */
        let mut starting_number = 1;
        let mut key_usages = Vec::new();
        // We iterate over all bits, check if the current bit is set and try to convert the
        // current value of starting_number to a KeyUsage variant. On every iteration, we divide
        // starting_number by two, until it equals 1 and thus cannot be divided any further.
        for bit in bitstring.raw_bytes().iter() {
            if *bit == 0 {
                // If the bit is 0, we can skip the current iteration, increment the starting_number
                // and continue with the next iteration.
                multiply_starting_number(&mut starting_number);
                continue;
            }
            if *bit != 1 {
                // If the bit is not 0 or 1, we are likely looking at the "unused bits" byte of the
                // BitString. We can safely ignore this byte.
                continue;
            }
            key_usages.push(KeyUsage::try_from(starting_number)?);
            if starting_number == 256 {
                // Stop the loop if starting_number is already 256.
                break;
            }
            multiply_starting_number(&mut starting_number);
        }
        Ok(KeyUsages::new(&key_usages))
    }

    /// Converts the KeyUsages to a [BitString].
    pub fn to_bitstring(self) -> BitString {
        let vec = self.key_usages;
        let mut encoded_numbers = [0u8; 2];
        let mut unused_bits: u8 = 0;
        /*
        If DecipherOnly is supposed to be set, we need to store this information as a separate
        byte. All other KeyUsages can be stored in the first byte.

        Normally, DigitalSignature would equal 1, ContentCommitment would equal 2, KeyEncipherment
        would equal 4, and so on. However, because of the way DER BitStrings are encoded, we need
        to reverse the order of the bits. This means that DigitalSignature has a value of 128, and
        DecipherOnly has a value of 1.

        We are adding these values to the u8 stored in the second byte of the encoded_numbers array.
         */
        for keyusage in vec.iter() {
            match *keyusage {
                KeyUsage::DigitalSignature => encoded_numbers[1] += 128,
                KeyUsage::ContentCommitment => encoded_numbers[1] += 64,
                KeyUsage::KeyEncipherment => encoded_numbers[1] += 32,
                KeyUsage::DataEncipherment => encoded_numbers[1] += 16,
                KeyUsage::KeyAgreement => encoded_numbers[1] += 8,
                KeyUsage::KeyCertSign => encoded_numbers[1] += 4,
                KeyUsage::CrlSign => encoded_numbers[1] += 2,
                KeyUsage::EncipherOnly => encoded_numbers[1] += 1,
                KeyUsage::DecipherOnly => encoded_numbers[0] += 128,
            }
        }
        let mut encoded_numbers_vec = encoded_numbers.to_vec();
        if encoded_numbers[0] == 0 {
            encoded_numbers_vec.remove(0);
            // {:08b} means that we want to format the number as a binary string with 8 bits.
            let binary = format!("{:08b}", encoded_numbers[1].to_be());
            for bit in binary.chars() {
                // If the bit is 0, increment the unused_bits counter.
                if bit == '0' {
                    unused_bits += 1;
                } else {
                    break;
                }
            }
        } else {
            // If encoded_numbers[0] is not 0, this means that DecipherOnly is set. Since only
            // DecipherOnly can be set in the first byte, we know that there have to be 7 unused
            // bits.
            unused_bits = 7;
        }
        BitString::new(unused_bits, encoded_numbers_vec)
            .expect("Error when converting KeyUsages to BitString. Please report this error to https://github.com/polyphony-chat/polyproto")
    }
}

impl From<KeyUsages> for BitString {
    fn from(value: KeyUsages) -> Self {
        value.to_bitstring()
    }
}

impl TryFrom<Attribute> for KeyUsages {
    type Error = ConversionError;

    fn try_from(value: Attribute) -> Result<Self, Self::Error> {
        if value.tag() != Tag::BitString {
            return Err(ConversionError::InvalidInput(InvalidInput::Malformed(
                format!("Expected BitString, found {}", value.tag(),),
            )));
        }
        match value.values.len() {
            0 => return Ok(KeyUsages::new(&[])),
            1 => (),
            _ => {
                return Err(ConversionError::InvalidInput(InvalidInput::Length {
                    min_length: 0,
                    max_length: 1,
                    actual_length: value.values.len().to_string(),
                }));
            }
        };
        let inner_value = value.values.get(0).expect("Illegal state. Please report this error to https://github.com/polyphony-chat/polyproto");
        KeyUsages::from_bitstring(BitString::from_der(inner_value.value())?)
    }
}

fn multiply_starting_number(number: &mut u32) {
    if !*number == 256 {
        *number *= 2;
    }
}

impl TryFrom<Extension> for KeyUsages {
    type Error = ConversionError;

    fn try_from(value: Extension) -> Result<Self, Self::Error> {
        if value.extn_id.to_string().as_str() != OID_KEY_USAGE {
            return Err(ConversionError::InvalidInput(InvalidInput::Malformed(
                format!(
                    "Expected OID {} for KeyUsages, found OID {}",
                    OID_KEY_USAGE, value.extn_id
                ),
            )));
        }
        let any = Any::from_der(value.extn_value.as_bytes())?;
        KeyUsages::from_bitstring(BitString::from_bytes(any.value())?)
    }
}

impl TryFrom<KeyUsages> for Attribute {
    type Error = ConversionError;

    fn try_from(value: KeyUsages) -> Result<Self, Self::Error> {
        let mut sov = SetOfVec::new();
        let bitstring = value.to_bitstring();
        sov.insert(Any::from_der(&bitstring.to_der()?)?)?;
        Ok(Attribute {
            oid: ObjectIdentifier::from_str(OID_KEY_USAGE)?,
            values: sov,
        })
    }
}

impl TryFrom<KeyUsages> for Extension {
    type Error = ConversionError;
    fn try_from(value: KeyUsages) -> Result<Self, Self::Error> {
        let bitstring = value.to_bitstring();
        let any = Any::from_der(&bitstring.to_der()?)?;
        Ok(Extension {
            extn_id: ObjectIdentifier::from_str(OID_KEY_USAGE)?,
            critical: true,
            extn_value: OctetString::new(any.to_der()?)?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
        let _bitstring = BitString::from(key_usages);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn key_usages_vec_sorts_correctly() {
        #[allow(clippy::useless_vec)]
        let mut vec = vec![
            KeyUsage::ContentCommitment,
            KeyUsage::EncipherOnly,
            KeyUsage::DataEncipherment,
            KeyUsage::DigitalSignature,
        ];
        vec.sort();
        assert!(*vec.first().unwrap() == KeyUsage::DigitalSignature);
        assert!(*vec.get(1).unwrap() == KeyUsage::ContentCommitment);
        assert!(*vec.get(2).unwrap() == KeyUsage::DataEncipherment);
        assert!(*vec.get(3).unwrap() == KeyUsage::EncipherOnly);
    }
}
