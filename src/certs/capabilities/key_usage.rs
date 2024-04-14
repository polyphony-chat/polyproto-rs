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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConversionError> {
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
        let bitstring = BitString::from_bytes(bytes)?;
        // The "starting number" is 2 to the power of len(bitstring) [<-pseudocode].
        // For a bit of length 8, this would be 2^8=256.
        let mut starting_number = 2u32.pow(bitstring.bit_len() as u32);
        let mut key_usages = Vec::new();
        // We iterate over all bits, check if the current bit is set and try to convert the
        // current value of starting_number to a KeyUsage variant. On every iteration, we divide
        // starting_number by two, until it equals 1 and thus cannot be divided any further.
        for bit in bitstring.bits() {
            match bit {
                true => 1u8,
                false => {
                    divide_starting_number(&mut starting_number);
                    continue;
                }
            };
            key_usages.push(KeyUsage::try_from(starting_number)?);
            if starting_number == 1 {
                // Stop the loop if starting_number is already 1.
                break;
            }
            divide_starting_number(&mut starting_number);
        }
        Ok(KeyUsages::new(&key_usages))
    }

    /// Converts the KeyUsages to a bitstring in little endian order.
    pub fn to_le_bits(mut self) -> [bool; 9] {
        self.key_usages.sort();
        self.key_usages.dedup();
        let mut bit_vec = [false; 9];
        for item in self.key_usages.into_iter() {
            match item {
                KeyUsage::DigitalSignature => bit_vec[0] = true,
                KeyUsage::ContentCommitment => bit_vec[1] = true,
                KeyUsage::KeyEncipherment => bit_vec[2] = true,
                KeyUsage::DataEncipherment => bit_vec[3] = true,
                KeyUsage::KeyAgreement => bit_vec[4] = true,
                KeyUsage::KeyCertSign => bit_vec[5] = true,
                KeyUsage::CrlSign => bit_vec[6] = true,
                KeyUsage::EncipherOnly => bit_vec[7] = true,
                KeyUsage::DecipherOnly => bit_vec[8] = true,
            }
        }
        bit_vec
    }

    /// Converts the KeyUsages to a bitstring in big endian order.
    pub fn to_be_bits(self) -> [bool; 9] {
        let mut bit_vec = self.to_le_bits();
        bit_vec.reverse();
        bit_vec
    }

    /// Converts the KeyUsages to a [BitString].
    pub fn to_bitstring(self) -> BitString {
        let bits = self.to_be_bits();
        let mut bytes = bits
            .iter()
            .map(|x| if *x { 1 } else { 0 })
            .collect::<Vec<u8>>();
        while bytes[0] == 0 {
            bytes.remove(0);
        }
        let mut unused_bits: u8 = 0;
        while bytes.len() % 8 != 0 {
            bytes.push(0);
            unused_bits += 1;
        }
        BitString::new(unused_bits, bytes)
            .expect("Error when converting KeyUsages to BitString. Please report this error")
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
        KeyUsages::from_bytes(inner_value.value())
    }
}

fn divide_starting_number(number: &mut u32) {
    if !*number == 1 {
        *number /= 2;
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
        // here we need to NOT just do .as_bytes() but to somehow get the actual value in this
        // octetstring
        // TODO
        KeyUsages::from_bytes(value.extn_value.as_bytes())
    }
}

impl TryFrom<KeyUsages> for Attribute {
    type Error = ConversionError;

    fn try_from(value: KeyUsages) -> Result<Self, Self::Error> {
        let mut sov = SetOfVec::new();
        let bitstring = value.to_bitstring();
        sov.insert(Any::from_der(&bitstring.to_der()?)?)
            .expect("wow");
        dbg!(&sov);
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
        let bitstring = BitString::from(key_usages);
        dbg!(bitstring);
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
        assert!(*vec.get(0).unwrap() == KeyUsage::DigitalSignature);
        assert!(*vec.get(1).unwrap() == KeyUsage::ContentCommitment);
        assert!(*vec.get(2).unwrap() == KeyUsage::DataEncipherment);
        assert!(*vec.get(3).unwrap() == KeyUsage::EncipherOnly);
    }
}
