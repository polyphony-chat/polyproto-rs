// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use regex::Regex;

use crate::Constrained;
use crate::errors::{ConstraintError, ERR_MSG_FEDERATION_ID_REGEX};

/// The regular expression for a valid `FederationId`.
pub static REGEX_FEDERATION_ID: &str = r"\b([a-z0-9._%+-]+)@([a-z0-9-]+(\.[a-z0-9-]+)*)$";
/// The regular expression for a valid domain name.
pub static REGEX_DOMAIN_NAME: &str = r"\b([a-z0-9._%+-]+)@([a-z0-9-]+(\.[a-z0-9-]+)*)$";

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Common types of federation identifiers.
pub enum Identifer {
    /// A "domain name", identifying an instance
    Instance(DomainName),
    /// A "federation ID", identifying a unique actor
    FederationId(FederationId),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
// TODO: Serde Serialize, Deserialize impl.
/// Domain names are what identify an instance.
pub struct DomainName {
    pub(crate) value: String,
}

impl DomainName {
    /// Validates input, then creates a new [DomainName].
    pub fn new(domain_name: &str) -> Result<Self, ConstraintError> {
        let regex = Regex::new(REGEX_DOMAIN_NAME).unwrap();
        if regex.is_match(domain_name) {
            Ok(Self {
                value: domain_name.to_string(),
            })
        } else {
            Err(ConstraintError::Malformed(Some(String::from(
                "Supplied domain name does not match regex",
            ))))
        }
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// A `FederationId` is a globally unique identifier for an actor in the context of polyproto.
pub struct FederationId {
    /// Must be unique on each instance.
    pub(crate) local_name: String,
    /// Includes top-level domain, second-level domain and other subdomains. Address which the actors' home server can be reached at.
    pub(crate) domain_name: String,
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
                local_name,
                domain_name,
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

    use super::{DomainName, FederationId};

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
}
