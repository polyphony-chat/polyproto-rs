// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::types::{Service, ServiceName};

use super::*;

impl Constrained for ServiceName {
    fn validate(&self, _target: Option<Target>) -> Result<(), ConstraintError> {
        let stringified = self.to_string();
        if stringified.len() < 2 || stringified.len() > 64 {
            return Err(ConstraintError::OutOfBounds {
                lower: 2,
                upper: 64,
                actual: stringified.len().to_string(),
                reason: "The length of the ServiceName is outside of the allowed bounds"
                    .to_string(),
            });
        }
        let regex =
            regex::Regex::new(r"[^[:lower:][:digit:]\-_]").expect("Failed to compile regex");
        if regex.is_match(&stringified) {
            return Err(ConstraintError::Malformed(Some(format!("The ServiceName contains invalid characters: \"{}\" contains characters that are not lowercase letters, digits, hyphens, or underscores", stringified))));
        }
        Ok(())
    }
}

// TODO: Add tests for the ServiceName constraint
