// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use super::super::spki::AlgorithmIdentifierOwned;
use der::asn1::BitString;
use der::pem::LineEnding;
use der::{Decode, DecodePem, Encode, EncodePem};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectPublicKeyInfo(spki::SubjectPublicKeyInfoOwned);

impl SubjectPublicKeyInfo {
    pub fn new(algorithm: AlgorithmIdentifierOwned, subject_public_key: BitString) -> Self {
        Self(spki::SubjectPublicKeyInfoOwned {
            algorithm: algorithm.into(),
            subject_public_key,
        })
    }

    /// Try to decode this type from PEM.
    pub fn from_pem(pem: impl AsRef<[u8]>) -> Result<Self, der::Error> {
        spki::SubjectPublicKeyInfo::from_pem(pem).map(Self)
    }
    /// Try to decode this type from DER.
    pub fn from_der(value: &[u8]) -> Result<Self, der::Error> {
        spki::SubjectPublicKeyInfo::from_der(value).map(Self)
    }

    /// Try to encode this type as PEM.
    pub fn to_pem(&self, line_ending: LineEnding) -> Result<String, der::Error> {
        self.0.to_pem(line_ending)
    }

    /// Try to encode this type as DER.
    pub fn to_der(&self) -> Result<Vec<u8>, der::Error> {
        self.0.to_der()
    }
}

impl From<spki::SubjectPublicKeyInfoOwned> for SubjectPublicKeyInfo {
    fn from(spki: spki::SubjectPublicKeyInfoOwned) -> Self {
        Self(spki)
    }
}

impl From<SubjectPublicKeyInfo> for spki::SubjectPublicKeyInfoOwned {
    fn from(spki: SubjectPublicKeyInfo) -> Self {
        spki.0
    }
}

impl Deref for SubjectPublicKeyInfo {
    type Target = spki::SubjectPublicKeyInfoOwned;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SubjectPublicKeyInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    use der::pem::LineEnding;
    use serde::de::Visitor;
    use serde::{Deserialize, Serialize};

    use super::SubjectPublicKeyInfo;
    struct SubjectPublicKeyInfoVisitor;

    impl Visitor<'_> for SubjectPublicKeyInfoVisitor {
        type Value = SubjectPublicKeyInfo;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a valid, PEM or DER encoded SubjectPublicKeyInfo")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            SubjectPublicKeyInfo::from_pem(v).map_err(serde::de::Error::custom)
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            SubjectPublicKeyInfo::from_der(v).map_err(serde::de::Error::custom)
        }
    }

    impl<'de> Deserialize<'de> for SubjectPublicKeyInfo {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(SubjectPublicKeyInfoVisitor)
        }
    }

    impl Serialize for SubjectPublicKeyInfo {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let pem = self
                .to_pem(LineEnding::default())
                .map_err(serde::ser::Error::custom)?;
            serializer.serialize_str(&pem)
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use der::asn1::BitString;
    use serde_json::json;
    use spki::ObjectIdentifier;

    use crate::types::spki::AlgorithmIdentifierOwned;

    use super::SubjectPublicKeyInfo;

    #[test]
    fn deserialize_serialize_spki_json() {
        let oids = [
            ObjectIdentifier::from_str("1.1.3.1").unwrap(),
            ObjectIdentifier::from_str("2.23.5672.1").unwrap(),
            ObjectIdentifier::from_str("0.3.1.1").unwrap(),
            ObjectIdentifier::from_str("1.2.3.4.5.6.7.8.9.0.12.3.4.5.6.67").unwrap(),
            ObjectIdentifier::from_str("1.2.1122").unwrap(),
        ];

        for oid in oids.into_iter() {
            let spki = SubjectPublicKeyInfo::new(
                AlgorithmIdentifierOwned::new(oid, None),
                BitString::from_bytes(&[0x00, 0x01, 0x02]).unwrap(),
            );
            let spki_json = json!(&spki);
            let spki2: SubjectPublicKeyInfo = serde_json::from_value(spki_json.clone()).unwrap();
            assert_eq!(spki, spki2);
        }
    }

    #[test]
    fn deserialize_serialize_spki_pem() {
        let oids = [
            ObjectIdentifier::from_str("1.1.3.1").unwrap(),
            ObjectIdentifier::from_str("2.23.5672.1").unwrap(),
            ObjectIdentifier::from_str("0.3.1.1").unwrap(),
            ObjectIdentifier::from_str("1.2.3.4.5.6.7.8.9.0.12.3.4.5.6.67").unwrap(),
            ObjectIdentifier::from_str("1.2.1122").unwrap(),
        ];

        for oid in oids.into_iter() {
            let spki = SubjectPublicKeyInfo::new(
                AlgorithmIdentifierOwned::new(oid, None),
                BitString::from_bytes(&[0x00, 0x01, 0x02]).unwrap(),
            );
            let spki_pem = spki.to_pem(der::pem::LineEnding::LF).unwrap();
            let spki2 = SubjectPublicKeyInfo::from_pem(spki_pem).unwrap();
            assert_eq!(spki, spki2);
        }
    }

    #[test]
    fn deserialize_serialize_spki_der() {
        let oids = [
            ObjectIdentifier::from_str("1.1.3.1").unwrap(),
            ObjectIdentifier::from_str("2.23.5672.1").unwrap(),
            ObjectIdentifier::from_str("0.3.1.1").unwrap(),
            ObjectIdentifier::from_str("1.2.3.4.5.6.7.8.9.0.12.3.4.5.6.67").unwrap(),
            ObjectIdentifier::from_str("1.2.1122").unwrap(),
        ];

        for oid in oids.into_iter() {
            let spki = SubjectPublicKeyInfo::new(
                AlgorithmIdentifierOwned::new(oid, None),
                BitString::from_bytes(&[0x00, 0x01, 0x02]).unwrap(),
            );
            let spki_der = spki.to_der().unwrap();
            let spki2 = SubjectPublicKeyInfo::from_der(&spki_der).unwrap();
            assert_eq!(spki, spki2);
        }
    }
}
