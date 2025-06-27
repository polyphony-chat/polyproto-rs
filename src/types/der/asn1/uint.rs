// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::hash::Hash;
use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use bigdecimal::num_bigint::BigUint;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Uint(pub der::asn1::Uint);

impl Hash for Uint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
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

impl From<der::asn1::Uint> for Uint {
    fn from(value: der::asn1::Uint) -> Self {
        Self(value)
    }
}

impl From<Uint> for der::asn1::Uint {
    fn from(value: Uint) -> Self {
        value.0
    }
}

impl Uint {
    pub fn as_inner(&self) -> &der::asn1::Uint {
        &self.0
    }

    pub fn as_inner_mut(&mut self) -> &mut der::asn1::Uint {
        &mut self.0
    }
}

impl Read for Uint {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.as_bytes().read(buf)
    }
}

impl TryFrom<Uint> for u64 {
    type Error = crate::errors::InvalidInput;

    fn try_from(value: Uint) -> Result<Self, Self::Error> {
        if value.as_bytes().len() > 8 {
            return Err(crate::errors::InvalidInput::Malformed(format!(
                "SerialNumber holds {} bytes, but is only allowed to hold a maximum of 8 bytes (64 bit unsigned integer)",
                value.as_bytes().len()
            )));
        }
        let mut buf = [0u8; 8];
        let mut value = value.as_bytes().to_vec();
        value.reverse();
        if value.as_slice().read(&mut buf).is_err() {
            Ok(0)
        } else {
            buf.reverse();
            Ok(u64::from_be_bytes(buf))
        }
    }
}

impl From<u64> for Uint {
    fn from(value: u64) -> Self {
        Uint(der::asn1::Uint::new(value.to_be_bytes().as_slice()).unwrap())
    }
}

impl From<&Uint> for BigUint {
    fn from(value: &Uint) -> Self {
        BigUint::from_bytes_be(value.as_bytes())
    }
}

impl From<Uint> for BigUint {
    fn from(value: Uint) -> Self {
        BigUint::from(&value)
    }
}

impl std::fmt::Display for Uint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(BigUint::from(self).to_string().as_str())
    }
}

impl FromStr for Uint {
    type Err = crate::errors::ConstraintError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Uint(::der::asn1::Uint::new(s.as_bytes()).map_err(|e| {
            crate::errors::ConstraintError::Malformed(Some(e.to_string()))
        })?))
    }
}

#[cfg(feature = "serde")]
mod serde {
    use super::*;
    use ::serde::{Deserialize, Serialize};

    impl<'de> Deserialize<'de> for Uint {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            todo!()
        }
    }

    impl Serialize for Uint {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: ::serde::Serializer,
        {
            todo!()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;

    #[test]
    fn test_from_str() {
        let str = "8491-6758-491367519432576928376514";
        let uint = Uint::from_str(str).unwrap();
    }

    #[test]
    fn biguint_from_uint() {
        let rust_uint = 2345897890234573497898023455902348u128;
        let asn1_uint = Uint::from(der::asn1::Uint::new(&rust_uint.to_be_bytes()).unwrap());
        let big_uint = BigUint::from(asn1_uint.clone());

        let mut rust_uint_be_bytes = dbg!(rust_uint.to_be_bytes().to_vec());
        rust_uint_be_bytes.remove(0);
        rust_uint_be_bytes.remove(0);
        let asn1_uint_be_bytes = dbg!(asn1_uint.as_bytes().to_vec());
        let big_uint_le_bytes = dbg!(big_uint.to_bytes_be());

        assert!(big_uint_le_bytes == asn1_uint_be_bytes.as_slice());
        assert!(rust_uint_be_bytes == asn1_uint_be_bytes.as_slice());

        assert_eq!(rust_uint.to_string(), asn1_uint.to_string());
        assert_eq!(big_uint.to_string(), asn1_uint.to_string());
    }

    #[test]
    fn uint_to_u64_and_vice_versa() {
        let u641 = 3761284836712u64;
        let uint = Uint::from(u641);
        let u642 = u64::try_from(uint).unwrap();
        assert_eq!(u641, u642)
    }

    #[test]
    fn uint_to_u64_fails_on_too_big_uint() {
        let big_number = u128::MAX.to_be_bytes();
        assert!(u64::try_from(Uint(der::asn1::Uint::new(&big_number).unwrap())).is_err());
        let big_number = (u64::MAX as u128 + 1).to_be_bytes();
        let uint = Uint(der::asn1::Uint::new(&big_number).unwrap());
        assert!(u64::try_from(uint).is_err());
    }
}
