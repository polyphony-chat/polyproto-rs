// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use spki::ObjectIdentifier;
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

/// Represents errors for invalid input in IdCsr or IdCert generation.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum InvalidInput {
    #[error("The der library has reported the following error with the input")]
    DerError(der::Error),
    #[error("subject_session_id MUST NOT exceed length limit of 32 characters")]
    SessionIdTooLong,
    #[error(
        "Cannot perform conversion, as input variant can not be converted to output. {reason:}"
    )]
    IncompatibleVariantForConversion { reason: String },
    #[error("Critical extension cannot be converted")]
    UnknownCriticalExtension { oid: ObjectIdentifier },
}

#[derive(Error, Debug, PartialEq, Clone)]
// TODO: Replace usages of InvalidInput::IncompatibleVariantForConversion with this Enum
pub enum UnsuccessfulConversion {
    #[error(
        "Cannot perform conversion, as input variant can not be converted to output. {reason:}"
    )]
    IncompatibleVariant { reason: String },
    #[error("Conversion failed due to invalid input")]
    InvalidInput(String),
}
