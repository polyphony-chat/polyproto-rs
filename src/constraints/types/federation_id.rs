// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use regex::Regex;

use crate::errors::ERR_MSG_FEDERATION_ID_REGEX;
use crate::types::{FederationId, REGEX_FEDERATION_ID};

use super::*;

impl Constrained for FederationId {
    fn validate(&self, _target: Option<Target>) -> Result<(), ConstraintError> {
        let fid_regex = Regex::new(REGEX_FEDERATION_ID).unwrap();
        match fid_regex.is_match(&self.inner) {
            true => Ok(()),
            false => Err(ConstraintError::Malformed(Some(
                ERR_MSG_FEDERATION_ID_REGEX.to_string(),
            ))),
        }
    }
}
