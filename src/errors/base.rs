// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Clone)]
pub enum ConstraintError {
    #[error("The value did not meet the set validation criteria and is considered malformed")]
    Malformed(Option<String>),
    #[error("The value was expected to be between {lower:?} and {upper:?} but was {actual:?}")]
    OutOfBounds {
        lower: i32,
        upper: i32,
        actual: String,
        reason: Option<String>,
    },
}
