// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::errors::{ERR_MSG_CHALLENGE_STRING_LENGTH, ERR_MSG_FEDERATION_ID_REGEX};
use crate::types::authorization::ChallengeString;
use crate::types::{FederationId, REGEX_FEDERATION_ID};
use regex::Regex;

use super::*;

impl Constrained for ChallengeString {
    fn validate(&self, _target: Option<Target>) -> Result<(), ConstraintError> {
        if self.challenge.len() < 32 || self.challenge.len() > 255 {
            return Err(ConstraintError::OutOfBounds {
                lower: 32,
                upper: 255,
                actual: self.challenge.len().to_string(),
                reason: ERR_MSG_CHALLENGE_STRING_LENGTH.to_string(),
            });
        }
        Ok(())
    }
}

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
