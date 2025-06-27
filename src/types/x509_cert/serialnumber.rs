// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use log::trace;

use crate::errors::{CertificateConversionError, ConstraintError, InvalidInput};
use crate::types::der::asn1::Uint;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Wrapper type around [x509_cert::serial_number::SerialNumber], providing serde support, if the
/// `serde` feature is enabled. See "De-/serialization value expectations" below for more
/// information.
///
///   [RFC 5280 Section 4.1.2.2.]  Serial Number
///
///   The serial number MUST be a positive integer assigned by the CA to
///   each certificate.  It MUST be unique for each certificate issued by a
///   given CA (i.e., the issuer name and serial number identify a unique
///   certificate).  CAs MUST force the serialNumber to be a non-negative
///   integer.
///
///   Given the uniqueness requirements above, serial numbers can be
///   expected to contain long integers.  Certificate users MUST be able to
///   handle serialNumber values up to 20 octets.  Conforming CAs MUST NOT
///   use serialNumber values longer than 20 octets.
///
///   Note: Non-conforming CAs may issue certificates with serial numbers
///   that are negative or zero.  Certificate users SHOULD be prepared to
///   gracefully handle such certificates.
///
/// ## De-/serialization value expectations
///
/// The serde de-/serialization implementation for [`SerialNumber`] expects a byte slice representing
/// a positive integer.
pub struct SerialNumber(pub(crate) ::x509_cert::serial_number::SerialNumber);

impl From<::x509_cert::serial_number::SerialNumber> for SerialNumber {
    fn from(inner: ::x509_cert::serial_number::SerialNumber) -> Self {
        SerialNumber(inner)
    }
}

impl From<SerialNumber> for ::x509_cert::serial_number::SerialNumber {
    fn from(value: SerialNumber) -> Self {
        value.0
    }
}

impl Deref for SerialNumber {
    type Target = ::x509_cert::serial_number::SerialNumber;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Uint> for SerialNumber {
    type Error = ConstraintError;

    fn try_from(value: Uint) -> Result<Self, Self::Error> {
        Ok(SerialNumber(
            x509_cert::serial_number::SerialNumber::new(value.as_bytes())
                .map_err(|e| ConstraintError::Malformed(Some(e.to_string())))?,
        ))
    }
}

impl DerefMut for SerialNumber {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl SerialNumber {
    /// Create a new [`SerialNumber`] from a byte slice.
    ///
    /// The byte slice **must** be big endian and represent a positive integer.
    pub fn from_bytes_be(bytes: &[u8]) -> Result<Self, x509_cert::der::Error> {
        x509_cert::serial_number::SerialNumber::new(bytes).map(Into::into)
    }

    /// Borrow the inner byte slice which contains the least significant bytes
    /// of a big endian integer value with all leading zeros stripped.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Try to convert the inner byte slice to a [u128].
    ///
    /// Returns an error if the byte slice is empty,
    /// or if the byte slice is longer than 16 bytes. Leading zeros of byte slices are stripped, so
    /// 17 bytes are allowed, if the first byte is zero.
    pub fn try_as_u128(&self) -> Result<u128, CertificateConversionError> {
        let mut bytes = self.as_bytes().to_vec();
        if bytes.is_empty() {
            return Err(InvalidInput::Length {
                min_length: 1,
                max_length: 16,
                actual_length: 1.to_string(),
            }
            .into());
        }
        if *bytes.first().unwrap() == 0 {
            bytes.remove(0);
        }
        trace!("bytes: {:?}", bytes);
        if bytes.len() > 16 {
            return Err(InvalidInput::Length {
                min_length: 1,
                max_length: 16,
                actual_length: bytes.len().to_string(),
            }
            .into());
        }
        let mut buf = [0u8; 16];
        buf[16 - bytes.len()..].copy_from_slice(&bytes);
        Ok(u128::from_be_bytes(buf))
    }
}

impl TryFrom<SerialNumber> for der::asn1::Uint {
    fn try_from(value: SerialNumber) -> Result<Self, Self::Error> {
        Self::new(value.0.as_bytes())
    }

    type Error = der::Error;
}

impl From<SerialNumber> for crate::types::der::asn1::Uint {
    #[allow(clippy::expect_used)]
    // Uints have up to 256 MiB of storage space, whereas SerialNumbers are limited to 160 bytes
    // in length. This conversion should never fail.
    //
    // See: <https://docs.rs/der/latest/der/struct.Length.html#:~:text=currently%20supported%3A%20256-,mib,-Source>
    fn from(value: SerialNumber) -> Self {
        der::asn1::Uint::new(value.0.as_bytes())
            .map(|v| v.into())
            .expect("This should never happen")
    }
}

impl std::fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&Uint::from(self.clone()).to_string())
    }
}

impl TryFrom<SerialNumber> for u128 {
    type Error = CertificateConversionError;

    fn try_from(value: SerialNumber) -> Result<Self, Self::Error> {
        value.try_as_u128()
    }
}

impl From<u128> for SerialNumber {
    fn from(value: u128) -> Self {
        // All u128 values are valid serial numbers, so we can unwrap
        #[allow(clippy::unwrap_used)]
        SerialNumber::from_bytes_be(&value.to_be_bytes()).unwrap()
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    use serde::de::Visitor;
    use serde::{Deserialize, Serialize};

    use super::SerialNumber;

    struct SerialNumberVisitor;

    impl<'de> Visitor<'de> for SerialNumberVisitor {
        type Value = SerialNumber;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a byte slice representing a positive integer")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            SerialNumber::from_bytes_be(v).map_err(serde::de::Error::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut bytes: Vec<u8> = Vec::new(); // Create a new Vec to store the bytes
            while let Some(byte) = seq.next_element()? {
                // "Iterate" over the sequence, assuming each element is a byte
                bytes.push(byte) // Push the byte to the Vec
            }
            SerialNumber::from_bytes_be(&bytes).map_err(serde::de::Error::custom) // Create a SerialNumber from the Vec
        }
    }

    impl<'de> Deserialize<'de> for SerialNumber {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(SerialNumberVisitor)
        }
    }

    impl Serialize for SerialNumber {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod test {
    use der::asn1::Uint;
    use log::trace;
    use serde_json::json;

    use crate::testing_utils::init_logger;

    use super::SerialNumber;

    #[test]
    fn try_from_uint() {
        init_logger();
        let serial_number = SerialNumber::from_bytes_be(&2347812387874u128.to_be_bytes()).unwrap();
        let uint = Uint::new(&2347812387874u128.to_be_bytes()).unwrap();
        let other_serial =
            SerialNumber::try_from(crate::types::der::asn1::Uint(uint.clone())).unwrap();
        dbg!(crate::types::der::asn1::Uint(uint).to_string());
        assert_eq!(serial_number, other_serial)
    }

    #[test]
    fn from_serial_number_for_uint() {
        let serial_number = SerialNumber::from_bytes_be(&2347812387874u128.to_be_bytes()).unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        // Small natural numbers
        let serial_number = SerialNumber::from_bytes_be(&0u128.to_be_bytes()).unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        let serial_number = SerialNumber::from_bytes_be(&1u128.to_be_bytes()).unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        let serial_number = SerialNumber::from_bytes_be(&255u128.to_be_bytes()).unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        // Medium-sized natural numbers
        let serial_number = SerialNumber::from_bytes_be(&65535u128.to_be_bytes()).unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        let serial_number = SerialNumber::from_bytes_be(&4294967295u128.to_be_bytes()).unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        // Large random natural numbers
        let serial_number =
            SerialNumber::from_bytes_be(&128253285483725236007410414782089762838u128.to_be_bytes())
                .unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        let serial_number =
            SerialNumber::from_bytes_be(&21879077042299220147540107698690186889u128.to_be_bytes())
                .unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        let serial_number =
            SerialNumber::from_bytes_be(&54955331587256710244358769277668724413u128.to_be_bytes())
                .unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        let serial_number =
            SerialNumber::from_bytes_be(&19245332277226247313033429008138887484u128.to_be_bytes())
                .unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        let serial_number =
            SerialNumber::from_bytes_be(&108840297003229100719348976033157371489u128.to_be_bytes())
                .unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        // Maximum u128 value
        let serial_number = SerialNumber::from_bytes_be(&u128::MAX.to_be_bytes()).unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        // Insanity
        let serial_number = SerialNumber::from_bytes_be(&[128; 19]).unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();

        let serial_number = SerialNumber::from_bytes_be(&[255; 19]).unwrap();
        let _uint: crate::types::der::asn1::Uint = serial_number.into();
    }

    #[test]
    fn serialize_deserialize() {
        init_logger();
        let serial_number = SerialNumber::from_bytes_be(&2347812387874u128.to_be_bytes()).unwrap();
        let serialized = json!(serial_number);
        trace!("is_array: {:?}", serialized.is_array());
        trace!("serialized: {serialized}");
        let deserialized: SerialNumber = serde_json::from_value(serialized).unwrap();

        assert_eq!(serial_number, deserialized);
    }

    #[test]
    fn serial_number_from_to_u128() {
        init_logger();
        let mut val = 0u128;
        loop {
            let serial_number = SerialNumber::from_bytes_be(&val.to_be_bytes()).unwrap();
            let json = json!(serial_number);
            let deserialized: SerialNumber = serde_json::from_value(json).unwrap();
            let u128 = deserialized.try_as_u128().unwrap();
            assert_eq!(u128, val);
            assert_eq!(deserialized, serial_number);
            if val == 0 {
                val = 1;
            }
            if val == u128::MAX {
                break;
            }
            val = match val.checked_mul(2) {
                Some(v) => v,
                None => u128::MAX,
            };
        }
    }

    #[test]
    fn try_as_u128() {
        init_logger();
        let mut val = 1u128;
        loop {
            let serial_number = SerialNumber::from_bytes_be(&val.to_be_bytes()).unwrap();
            let u128 = serial_number.try_as_u128().unwrap();
            assert_eq!(u128, val);
            trace!("u128: {u128}");
            if val == u128::MAX {
                break;
            }
            val = match val.checked_mul(2) {
                Some(v) => v,
                None => u128::MAX,
            };
        }
    }

    #[test]
    fn hundredsixty_bit_number() {
        init_logger();
        let bytes = [3u8; 20];
        let serial_number = super::SerialNumber::from_bytes_be(&bytes).unwrap();
        log::debug!("Got serial_number {serial_number:?}");
    }
}
