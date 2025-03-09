// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use regex::Regex;

use crate::Constrained;
use crate::errors::{ConstraintError, ERR_MSG_FEDERATION_ID_REGEX};

/// The regular expression for a valid `FederationId`.
pub static REGEX_FEDERATION_ID: &str = r"\b([a-z0-9._%+-]+)@([a-z0-9-]+(\.[a-z0-9-]+)*)$";

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

impl std::fmt::Display for FederationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local_name, self.domain_name)
    }
}
