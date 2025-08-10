// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use regex::Regex;

use crate::types::{DomainName, REGEX_DOMAIN_NAME};

use super::*;

impl Constrained for DomainName {
    fn validate(&self, _target: Option<Target>) -> Result<(), ConstraintError> {
        if self.value.trim().is_empty() {
            return Err(ConstraintError::Malformed(Some(
                "HomeServerDN must have a non-empty domain name".to_string(),
            )));
        }
        #[allow(clippy::unwrap_used)]
        let regex = Regex::new(REGEX_DOMAIN_NAME).unwrap();
        if regex.is_match(&self.value) {
            Ok(())
        } else {
            Err(ConstraintError::Malformed(Some(String::from(
                "Supplied domain name does not match regex",
            ))))
        }
    }
}
