// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io::Read;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Uint(pub der::asn1::Uint);

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
            return Err(crate::errors::InvalidInput::Length {
                min_length: 0,
                max_length: 8,
                actual_length: value.as_bytes().len().to_string(),
            });
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
