// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use der::Any;
use der::asn1::PrintableString;
use regex::Regex;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::name::DirectoryString;
use x509_cert::name::{RdnSequence, RelativeDistinguishedName};

use crate::errors::{ConstraintError, ERR_MSG_FEDERATION_ID_REGEX, InvalidInput};
use crate::types::local_name::LocalName;
use crate::{Constrained, OID_RDN_DOMAIN_COMPONENT, OID_RDN_UID};

/// The regular expression for a valid `FederationId`.
pub static REGEX_FEDERATION_ID: &str = r"\b([a-z0-9._%+-]+)@([a-z0-9-]+(\.[a-z0-9-]+)*)$";
/// The regular expression for a valid domain name.
pub static REGEX_DOMAIN_NAME: &str = r"\b([a-z0-9-]+(\.[a-z0-9-]+)*)$";

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Common types of federation identifiers.
pub enum Identifer {
    /// A "domain name", identifying an instance
    Instance(DomainName),
    /// A "federation ID", identifying a unique actor
    FederationId(FederationId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Domain names are what identify an instance.
pub struct DomainName {
    pub(crate) value: String,
}

impl DomainName {
    /// Validates input, then creates a new [DomainName].
    pub fn new(domain_name: &str) -> Result<Self, ConstraintError> {
        let dn = Self {
            value: domain_name.to_string(),
        };
        dn.validate(None)?;
        Ok(dn)
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl TryFrom<&[AttributeTypeAndValue]> for DomainName {
    type Error = ConstraintError;

    fn try_from(values: &[AttributeTypeAndValue]) -> Result<Self, Self::Error> {
        if let Some(non_rdn) = values
            .iter()
            .find(|element| element.oid != OID_RDN_DOMAIN_COMPONENT)
        {
            return Err(ConstraintError::Malformed(Some(format!(
                "Found a value with OID {} when expecting only DomainComponent values of OID {OID_RDN_DOMAIN_COMPONENT}",
                non_rdn.oid
            ))));
        }
        let mut domain_components = Vec::with_capacity(values.len());
        for value in values.iter() {
            let attribute_value = value.value.value();
            let string = String::from_utf8_lossy(attribute_value);
            domain_components.push(string);
        }
        DomainName::new(domain_components.join(".").as_str())
    }
}

impl TryFrom<DomainName> for AttributeTypeAndValue {
    type Error = der::Error;

    fn try_from(value: DomainName) -> Result<Self, Self::Error> {
        let printable_string =
            DirectoryString::PrintableString(PrintableString::new(value.value.as_str())?);
        Ok(Self {
            oid: OID_RDN_DOMAIN_COMPONENT,
            value: Any::encode_from(&printable_string)?,
        })
    }
}

impl TryFrom<DomainName> for RdnSequence {
    fn try_from(value: DomainName) -> Result<Self, Self::Error> {
        let mut rdns = Vec::new();
        for split in value.value.split('.') {
            rdns.push(RelativeDistinguishedName::from_str(split)?);
        }
        Ok(RdnSequence(rdns))
    }

    type Error = der::Error;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// A `FederationId` is a globally unique identifier for an actor in the context of polyproto.
pub struct FederationId {
    /// Must be unique on each instance.
    pub(crate) local_name: LocalName,
    /// Includes top-level domain, second-level domain and other subdomains. Address which the actors' home server can be reached at.
    pub(crate) domain_name: DomainName,
}

impl FederationId {
    /// Validates input, then creates a new `FederationId`.
    pub fn new(id: &str) -> Result<Self, ConstraintError> {
        let regex = Regex::new(REGEX_FEDERATION_ID).unwrap();
        let matches = {
            let mut x = String::new();
            regex
                .find_iter(id)
                .map(|y| y.as_str())
                .for_each(|y| x.push_str(y));
            x
        };
        if regex.is_match(&matches) {
            let separator_position = id.find('@').unwrap();
            let local_name = id[0..separator_position].to_string();
            let domain_name = id[separator_position + 1..].to_string();
            let fid = Self {
                local_name: LocalName::new(&local_name)?,
                domain_name: DomainName::new(&domain_name)?,
            };
            fid.validate(None)?;
            Ok(fid)
        } else {
            Err(ConstraintError::Malformed(Some(
                ERR_MSG_FEDERATION_ID_REGEX.to_string(),
            )))
        }
    }
}

impl TryFrom<&str> for FederationId {
    type Error = ConstraintError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        FederationId::new(value)
    }
}

impl std::fmt::Display for FederationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local_name, self.domain_name)
    }
}

#[cfg(feature = "serde")]
mod serde {
    use serde::de::Visitor;
    use serde::{Deserialize, Serialize};

    use crate::errors::{ERR_MSG_DOMAIN_NAME_REGEX, ERR_MSG_FEDERATION_ID_REGEX};

    use super::{DomainName, FederationId, Identifer};

    struct FidVisitor;

    impl Visitor<'_> for FidVisitor {
        type Value = FederationId;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a valid polyproto federation ID")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            FederationId::new(v).map_err(|_| E::custom(ERR_MSG_FEDERATION_ID_REGEX.to_string()))
        }
    }

    impl<'de> Deserialize<'de> for FederationId {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_str(FidVisitor)
        }
    }

    impl Serialize for FederationId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(&self.to_string())
        }
    }

    struct DnVisitor;

    impl Visitor<'_> for DnVisitor {
        type Value = DomainName;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a valid domain name (please open a bug report if your domain name is valid and still caused this error)")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            DomainName::new(v).map_err(|_| E::custom(ERR_MSG_DOMAIN_NAME_REGEX.to_string()))
        }
    }

    impl<'de> Deserialize<'de> for DomainName {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_str(DnVisitor)
        }
    }

    impl Serialize for DomainName {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(&self.to_string())
        }
    }

    struct IdVisitor;

    impl Visitor<'_> for IdVisitor {
        type Value = Identifer;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a valid DomainName or FederationId")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if let Ok(fid) = FederationId::new(v) {
                Ok(Identifer::FederationId(fid) as Self::Value)
            } else if let Ok(dn) = DomainName::new(v) {
                Ok(Identifer::Instance(dn) as Self::Value)
            } else {
                Err(E::custom(
                    "passed string is neither a valid DomainName nor a valid FederationId",
                ))
            }
        }
    }

    impl<'de> Deserialize<'de> for Identifer {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_str(IdVisitor)
        }
    }

    impl Serialize for Identifer {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self {
                Identifer::Instance(domain_name) => domain_name.serialize(serializer),
                Identifer::FederationId(federation_id) => federation_id.serialize(serializer),
            }
        }
    }
}

impl TryFrom<AttributeTypeAndValue> for FederationId {
    type Error = ConstraintError;

    fn try_from(value: AttributeTypeAndValue) -> Result<Self, Self::Error> {
        if value.oid != OID_RDN_UID {
            return Err(InvalidInput::Malformed(format!(
                "This value has OID {}, which does not match OID {OID_RDN_UID}",
                value.oid
            ))
            .into());
        }
        let attribute_value = value.value.value();
        let string = String::from_utf8_lossy(attribute_value);
        FederationId::new(&string)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use der::Any;
    use x509_cert::ext::pkix::name::DirectoryString;

    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn from_attribute_type_and_value() {
        let directory_string = DirectoryString::Utf8String(String::from("input@in.put"));
        let attribute_and_value = AttributeTypeAndValue {
            oid: OID_RDN_UID,
            value: Any::encode_from(&directory_string).unwrap(),
        };
        assert!(FederationId::try_from(attribute_and_value).is_ok());

        let directory_string = DirectoryString::Utf8String(String::from("input@in.put"));
        let attribute_and_value = AttributeTypeAndValue {
            oid: OID_RDN_UID,
            value: Any::encode_from(&directory_string).unwrap(),
        };
        assert!(FederationId::try_from(attribute_and_value).is_err())
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn domain_name_from_attribute_type_and_value_success() {
        // Test successful parsing with valid domain components
        let domain_components = vec![
            AttributeTypeAndValue {
                oid: OID_RDN_DOMAIN_COMPONENT,
                value: Any::encode_from(&DirectoryString::Utf8String("example".to_string()))
                    .unwrap(),
            },
            AttributeTypeAndValue {
                oid: OID_RDN_DOMAIN_COMPONENT,
                value: Any::encode_from(&DirectoryString::Utf8String("com".to_string())).unwrap(),
            },
        ];

        let result = DomainName::try_from(domain_components.as_slice());
        assert!(result.is_ok());
        let domain_name = result.unwrap();
        assert_eq!(domain_name.to_string(), "example.com");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn domain_name_from_attribute_type_and_value_invalid_oid() {
        // Test error case with invalid OID
        let invalid_components = vec![
            AttributeTypeAndValue {
                oid: OID_RDN_DOMAIN_COMPONENT,
                value: Any::encode_from(&DirectoryString::Utf8String("example".to_string()))
                    .unwrap(),
            },
            AttributeTypeAndValue {
                oid: OID_RDN_UID, // Wrong OID - should be OID_RDN_DOMAIN_COMPONENT
                value: Any::encode_from(&DirectoryString::Utf8String("com".to_string())).unwrap(),
            },
        ];

        let result = DomainName::try_from(invalid_components.as_slice());
        assert!(result.is_err());
        match result.unwrap_err() {
            ConstraintError::Malformed(Some(msg)) => {
                assert!(msg.contains("Found a value with OID"));
                assert!(msg.contains("when expecting only DomainComponent values"));
            }
            _ => panic!("Expected ConstraintError::Malformed with message"),
        }
    }

    #[test]
    fn domain_name_from_empty_attribute_array() {
        // Test edge case with empty input
        let empty_components: Vec<AttributeTypeAndValue> = vec![];
        assert!(DomainName::try_from(Vec::new().as_slice()).is_err());
        let result = DomainName::try_from(empty_components.as_slice());

        // Empty input should attempt to create an empty domain name, which should fail validation
        assert!(result.is_err());
    }
}
