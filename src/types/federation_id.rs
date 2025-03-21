// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use regex::Regex;

use crate::errors::{ConstraintError, ERR_MSG_FEDERATION_ID_REGEX};
use crate::Constrained;

/// The regular expression for a valid `FederationId`.
pub static REGEX_FEDERATION_ID: &str = r"\b([a-z0-9._%+-]+)@([a-z0-9-]+(\.[a-z0-9-]+)*)$";

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize))]
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
    use serde::Deserialize;

    use crate::errors::ERR_MSG_FEDERATION_ID_REGEX;

    use super::FederationId;

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
}
