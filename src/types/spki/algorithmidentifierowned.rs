// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use der::{Any, Decode, Encode};
use spki::ObjectIdentifier;

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
/// `AlgorithmIdentifier` reference which has `Any` parameters.
///
/// A wrapper around `spki::AlgorithmIdentifierOwned`, which provides `serde` support, if enabled by
/// the `serde` feature.
///
/// ## De-/Serialization expectations
///
/// This type expects a DER encoded AlgorithmIdentifier with optional der::Any parameters. The DER
/// encoded data has to be provided in the form of an array of bytes. Types that fulfill this
/// expectation are, for example, `&[u8]`, `Vec<u8>` and `&[u8; N]`.
pub struct AlgorithmIdentifierOwned(spki::AlgorithmIdentifierOwned);

impl AlgorithmIdentifierOwned {
    /// Create a new `AlgorithmIdentifierOwned`.
    pub fn new(oid: ObjectIdentifier, parameters: Option<Any>) -> Self {
        Self(spki::AlgorithmIdentifierOwned { oid, parameters })
    }

    /// Try to encode this type as DER.
    pub fn to_der(&self) -> Result<Vec<u8>, der::Error> {
        self.0.to_der()
    }

    /// Try to decode this type from DER.
    pub fn from_der(bytes: &[u8]) -> Result<AlgorithmIdentifierOwned, der::Error> {
        spki::AlgorithmIdentifierOwned::from_der(bytes).map(Self)
    }
}

impl Deref for AlgorithmIdentifierOwned {
    type Target = spki::AlgorithmIdentifierOwned;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AlgorithmIdentifierOwned {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<spki::AlgorithmIdentifierOwned> for AlgorithmIdentifierOwned {
    fn from(value: spki::AlgorithmIdentifierOwned) -> Self {
        Self(value)
    }
}

impl From<AlgorithmIdentifierOwned> for spki::AlgorithmIdentifierOwned {
    fn from(value: AlgorithmIdentifierOwned) -> Self {
        value.0
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    use super::AlgorithmIdentifierOwned;
    use serde::de::Visitor;
    use serde::{Deserialize, Serialize};
    struct AlgorithmIdentifierVisitor;

    impl<'de> Visitor<'de> for AlgorithmIdentifierVisitor {
        type Value = AlgorithmIdentifierOwned;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter
                .write_str("a valid DER encoded byte slice representing an AlgorithmIdentifier")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            AlgorithmIdentifierOwned::from_der(v).map_err(serde::de::Error::custom)
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
            AlgorithmIdentifierOwned::from_der(&bytes).map_err(serde::de::Error::custom)
        }
    }

    impl<'de> Deserialize<'de> for AlgorithmIdentifierOwned {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_bytes(AlgorithmIdentifierVisitor)
        }
    }

    impl Serialize for AlgorithmIdentifierOwned {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let der = self.to_der().map_err(serde::ser::Error::custom)?;
            serializer.serialize_bytes(&der)
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use der::asn1::BitString;
    use der::{Any, Decode, Encode};
    use log::trace;
    use serde_json::json;
    use spki::ObjectIdentifier;

    use crate::testing_utils::init_logger;

    use super::AlgorithmIdentifierOwned;

    #[test]
    fn de_serialize() {
        init_logger();
        let oid = ObjectIdentifier::from_str("1.1.1.4.5").unwrap();
        let alg = AlgorithmIdentifierOwned::new(oid, None);
        let json = json!(alg);
        let deserialized: AlgorithmIdentifierOwned = serde_json::from_value(json).unwrap();
        assert_eq!(alg, deserialized);
        trace!("deserialized: {:?}", deserialized);
        trace!("original: {:?}", alg);

        let bytes = [48, 6, 6, 3, 43, 6, 1, 5, 1, 4, 5, 5, 23, 2, 0, 0];
        let bitstring = BitString::from_bytes(&bytes).unwrap();
        let alg = AlgorithmIdentifierOwned::new(
            oid,
            Some(Any::from_der(&bitstring.to_der().unwrap()).unwrap()),
        );
        let json = json!(alg);
        let deserialized: AlgorithmIdentifierOwned = serde_json::from_value(json).unwrap();
        trace!("deserialized: {:?}", deserialized);
        trace!("original: {:?}", alg);
        assert_eq!(alg, deserialized);
    }
}
