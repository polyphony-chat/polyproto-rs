// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use regex::Regex;

use crate::errors::base::ConstraintError;
use crate::errors::ERR_MSG_FEDERATION_ID_REGEX;
use crate::Constrained;

pub static REGEX_FEDERATION_ID: &str = r"\b([a-z0-9._%+-]+)@([a-z0-9-]+(\.[a-z0-9-]+)*)";

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FederationId {
    pub(crate) inner: String,
}

impl Deref for FederationId {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for FederationId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
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
            let fid = Self {
                inner: matches.to_string(),
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
        write!(f, "{}", self.inner)
    }
}
