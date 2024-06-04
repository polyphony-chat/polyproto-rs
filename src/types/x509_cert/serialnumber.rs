// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

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
pub struct SerialNumber(::x509_cert::serial_number::SerialNumber);

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

impl DerefMut for SerialNumber {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl SerialNumber {
    /// Create a new [`SerialNumber`] from a byte slice.
    ///
    /// The byte slice **must** represent a positive integer.
    pub fn new(bytes: &[u8]) -> Result<Self, x509_cert::der::Error> {
        x509_cert::serial_number::SerialNumber::new(bytes).map(Into::into)
    }

    /// Borrow the inner byte slice which contains the least significant bytes
    /// of a big endian integer value with all leading zeros stripped.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
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
            SerialNumber::new(v).map_err(serde::de::Error::custom)
        }
    }

    impl<'de> Deserialize<'de> for SerialNumber {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_bytes(SerialNumberVisitor)
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
