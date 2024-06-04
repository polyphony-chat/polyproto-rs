// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use crate::errors::ConversionError;

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
/// Unsigned arbitrary precision `ASN.1 INTEGER` type.
///
/// Provides heap-allocated storage for big endian bytes which comprise an unsigned integer value.
///
/// Intended for use cases like very large integers that are used in cryptographic applications (e.g. keys, signatures).
///
/// Wrapper around `der::asn1::Uint` to provide `From<u128>` and `TryFrom<Uint>` implementations, as
/// well as serde support, if the `serde` feature is enabled.
///
/// ## De-/Serialization value expectations
///
/// The implementation of serde de-/serialization for this type expects the value to be a valid, unsigned integer, up to 128 bits.
pub struct Uint(der::asn1::Uint);

impl Uint {
    pub fn new(bytes: &[u8]) -> Result<Self, der::Error> {
        der::asn1::Uint::new(bytes).map(Into::into)
    }
}

impl From<der::asn1::Uint> for Uint {
    fn from(u: der::asn1::Uint) -> Self {
        Self(u)
    }
}

impl From<Uint> for der::asn1::Uint {
    fn from(u: Uint) -> Self {
        u.0
    }
}

impl From<u128> for Uint {
    fn from(value: u128) -> Self {
        der::asn1::Uint::new(value.to_be_bytes().as_slice())
            .unwrap()
            .into()
    }
}

impl TryFrom<Uint> for u128 {
    type Error = ConversionError;
    fn try_from(value: Uint) -> Result<Self, Self::Error> {
        let bytes = value.0.as_bytes();
        if bytes.len() > 16 {
            return Err(crate::errors::InvalidInput::Length {
                min_length: 0,
                max_length: 16,
                actual_length: bytes.len().to_string(),
            }
            .into());
        }
        let mut buf = [0u8; 16];
        buf[16 - bytes.len()..].copy_from_slice(bytes);
        Ok(u128::from_be_bytes(buf))
    }
}

impl Deref for Uint {
    type Target = der::asn1::Uint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Uint {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    use serde::de::Visitor;
    use serde::{Deserialize, Serialize};

    use super::Uint;

    struct UintVisitor;

    impl<'de> Visitor<'de> for UintVisitor {
        type Value = Uint;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an unsigned integer up to 128 bits in size")
        }

        fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Uint::from(v))
        }
    }

    impl<'de> Deserialize<'de> for Uint {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_u128(UintVisitor)
        }
    }

    impl Serialize for Uint {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer
                .serialize_u128(u128::try_from(self.clone()).map_err(serde::ser::Error::custom)?)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_u128_from_uint() {
        let mut val = 1u128;
        while val < u128::MAX {
            log::debug!("Uint from u128: {}", val);
            let uint = Uint::from(val);
            assert_eq!(val, u128::try_from(uint).unwrap());
            val = val.checked_mul(2).unwrap_or(u128::MAX);
        }
    }

    #[test]
    fn test_de_serialization() {
        let mut val = 1u128;
        while val < u128::MAX {
            log::debug!("Uint from u128: {}", val);
            let uint: Uint = Uint::from(val);
            let serialized = serde_json::to_string(&uint).unwrap();
            log::debug!("Serialized: {}", serialized);
            let deserialized: Uint = serde_json::from_str(&serialized).unwrap();
            assert_eq!(val, u128::try_from(deserialized).unwrap());
            val = val.checked_mul(2).unwrap_or(u128::MAX);
        }
    }
}
