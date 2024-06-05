// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Clone)]
/// Constraint validation errors.
pub enum ConstraintError {
    #[error("The value did not meet the set validation criteria and is considered malformed")]
    /// The value did not meet the set validation criteria and is considered malformed
    Malformed(Option<String>),
    #[error("The value was expected to be between {lower:?} and {upper:?} but was {actual:?}")]
    /// A value is out of bounds
    OutOfBounds {
        /// The lower bound of the value
        lower: i32,
        /// The upper bound of the value
        upper: i32,
        /// The actual value
        actual: String,
        /// Additional context
        reason: String,
    },
}

/// Represents errors for invalid input. Differs from [ConstraintError], in that `ConstraintError` is
/// only used on types implementing the [crate::Constrained] trait.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum InvalidInput {
    #[error("The value is malformed and cannot be used as input: {0}")]
    /// The value is malformed and cannot be used as input
    Malformed(String),
    #[error("The value was expected to be between {min_length:?} and {max_length:?} but was {actual_length:?}")]
    /// A value is out of bounds
    Length {
        /// The minimum length of the value
        min_length: usize,
        /// The maximum length of the value
        max_length: usize,
        /// The actual length of the value
        actual_length: String,
    },
}
