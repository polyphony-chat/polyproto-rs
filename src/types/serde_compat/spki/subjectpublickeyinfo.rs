// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use super::super::spki::AlgorithmIdentifierOwned;
use der::asn1::BitString;
use der::pem::LineEnding;
use der::{Decode, DecodePem, Encode, EncodePem};
use serde::de::Visitor;
use serde::{Deserialize, Serialize};

use crate::types::LikeSubjectPublicKeyInfo;

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

struct SubjectPublicKeyInfoVisitor;

impl<'de> Visitor<'de> for SubjectPublicKeyInfoVisitor {
    type Value = SubjectPublicKeyInfo;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter
            .write_str("This visitor expects a valid, PEM or DER encoded SubjectPublicKeyInfo.")
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

impl LikeSubjectPublicKeyInfo for SubjectPublicKeyInfo {
    fn new(algorithm: AlgorithmIdentifierOwned, subject_public_key: BitString) -> Self {
        spki::SubjectPublicKeyInfoOwned {
            algorithm: algorithm.into(),
            subject_public_key,
        }
        .into()
    }
}

// TODO: TESTS
