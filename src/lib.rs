// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*!

# polyproto

(Generic) Rust types and traits to quickly get a
[polyproto](https://docs.polyphony.chat/Protocol%20Specifications/core/) implementation up and
running.

## Implementing polyproto

**The crate is currently in very early (alpha) development. A lot of functionality is missing, and
things may break or change at any point in time.**

This crate extends upon types offered by [der](https://crates.io/crates/der) and
[spki](https://crates.io/crates/spki). As such, these crates are required dependencies for
projects looking to implement polyproto.

Start by implementing the trait [crate::signature::Signature] for a signature algorithm of your
choice. Popular crates for cryptography and signature algorithms supply their own `PublicKey` and
`PrivateKey` types. You should extend upon these types with your own structs and implement the
[crate::key] traits for these new structs.

You can then use the [crate::certs] types to build certificates using your implementations of the
aforementioned traits.

## Cryptography

This crate provides no cryptographic functionality whatsoever; its sole purpose is to aid in
implementing polyproto by transforming the
[polyproto specification](https://docs.polyphony.chat/Protocol%20Specifications/core/) into
well-defined yet adaptable Rust types.


*/

#[warn(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    clippy::unnecessary_mut_passed
)]
#[deny(clippy::unwrap_used, clippy::todo, clippy::unimplemented)]
#[forbid(unsafe_code)]

/// Generic polyproto certificate types and traits.
pub mod certs;
/// Generic polyproto public- and private key traits.
pub mod key;
/// Generic polyproto signature traits.
pub mod signature;

pub(crate) mod constraints;

use std::fmt::Debug;

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("Conversion from TbsCertificate to IdCertTbs failed")]
    TbsCertToIdCert(#[from] TbsCertToIdCert),
    #[error("Conversion from IdCertTbs to TbsCertificate failed")]
    IdCertToTbsCert(#[from] IdCertToTbsCert),
    #[error("Invalid input cannot be handled")]
    InvalidInput(#[from] InvalidInput),
    #[error("Value failed to meet constraints")]
    ConstraintError(#[from] ConstraintError),
}

/// Error type covering possible failures when converting a [x509_cert::TbsCertificate]
/// to a [crate::cert::IdCertTbs]
#[derive(Error, Debug, PartialEq, Clone, Copy)]
pub enum TbsCertToIdCert {
    #[error("field 'subject_unique_id' was None. Expected: Some(der::asn1::BitString)")]
    SubjectUid,
    #[error("field 'extensions' was None. Expected: Some(x509_cert::ext::Extensions)")]
    Extensions,
    #[error("Supplied integer too long")]
    Signature(der::Error),
}

/// Error type covering possible failures when converting a [crate::cert::IdCertTbs]
/// to a [x509_cert::TbsCertificate]
#[derive(Error, Debug, PartialEq, Clone, Copy)]
pub enum IdCertToTbsCert {
    #[error("Serial number could not be converted")]
    SerialNumber(der::Error),
}

/// Represents errors for invalid input in IdCsr or IdCert generation.
#[derive(Error, Debug, PartialEq, Clone, Copy)]
pub enum InvalidInput {
    #[error("The der library has reported the following error with the input")]
    DerError(der::Error),
    #[error("subject_session_id MUST NOT exceed length limit of 32 characters")]
    SessionIdTooLong,
}

impl From<der::Error> for InvalidInput {
    fn from(value: der::Error) -> Self {
        Self::DerError(value)
    }
}

impl From<der::Error> for Error {
    fn from(value: der::Error) -> Self {
        Self::InvalidInput(value.into())
    }
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum ConstraintError {
    #[error("The value did not meet the set validation criteria and is considered malformed")]
    Malformed,
    #[error("The value was expected to be between {lower:?} and {upper:?} but was {actual:?}")]
    OutOfBounds {
        lower: i32,
        upper: i32,
        actual: String,
    },
}

/// Traits implementing [Constrained] can be validated to be well-formed. This does not guarantee
/// that a validated type will always be *correct* in the context it is in.
///
/// ### Example
///
/// The password "123" might be well-formed, as in, it meets the validation criteria specified by
/// the system. However, this makes no implications about "123" being the correct password for a
/// given user account.
pub(crate) trait Constrained {
    fn validate(&self) -> Result<(), ConstraintError>;
}

#[cfg(test)]
mod test {
    use der::asn1::Uint;
    use x509_cert::certificate::Profile;
    use x509_cert::serial_number::SerialNumber;

    #[derive(Clone, PartialEq, Eq, Debug)]
    enum TestProfile {}

    impl Profile for TestProfile {}

    fn strip_leading_zeroes(bytes: &[u8]) -> &[u8] {
        if let Some(stripped) = bytes.strip_prefix(&[0u8]) {
            stripped
        } else {
            bytes
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_convert_serial_number() {
        let biguint = Uint::new(&[10u8, 240u8]).unwrap();
        assert_eq!(biguint.as_bytes(), &[10u8, 240u8]);
        let serial_number: SerialNumber<TestProfile> =
            SerialNumber::new(biguint.as_bytes()).unwrap();
        assert_eq!(
            strip_leading_zeroes(serial_number.as_bytes()),
            biguint.as_bytes()
        );

        let biguint = Uint::new(&[240u8, 10u8]).unwrap();
        assert_eq!(biguint.as_bytes(), &[240u8, 10u8]);
        let serial_number: SerialNumber<TestProfile> =
            SerialNumber::new(biguint.as_bytes()).unwrap();
        assert_eq!(
            strip_leading_zeroes(serial_number.as_bytes()),
            biguint.as_bytes()
        );
    }
}
