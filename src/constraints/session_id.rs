// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;

impl Constrained for SessionId {
    /// [SessionId] must be longer than 0 and not longer than 32 characters to be deemed valid.
    fn validate(&self, _target: Option<Target>) -> Result<(), ConstraintError> {
        if self.len() > Length::new(32) || self.len() == Length::ZERO {
            return Err(ConstraintError::OutOfBounds {
                lower: 1,
                upper: 32,
                actual: self.len().to_string(),
                reason: "SessionId too long".to_string(),
            });
        }
        Ok(())
    }
}
