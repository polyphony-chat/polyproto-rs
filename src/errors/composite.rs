// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use spki::ObjectIdentifier;
use thiserror::Error;

use super::base::{ConstraintError, InvalidInput};

#[derive(Error, Debug, PartialEq, Clone)]
/// Errors that can occur when validating a certificate
pub enum InvalidCert {
    #[error(transparent)]
    /// Signature or public key are invalid
    PublicKeyError(#[from] PublicKeyError),
    #[error(transparent)]
    /// The certificate does not pass validation of polyproto constraints
    InvalidProperties(#[from] ConstraintError),
    #[error("The validity period of the certificate is invalid, or the certificate is expired")]
    /// The certificate is expired or has an invalid validity period
    InvalidValidity,
}

#[derive(Error, Debug, PartialEq, Hash, Clone, Copy)]
/// Errors related to Public Keys and Signatures
pub enum PublicKeyError {
    #[error("The signature does not match the data")]
    /// The signature does not match the data or the signature is malformed
    BadSignature,
    #[error("The provided PublicKeyInfo could not be made into a PublicKey")]
    /// The provided PublicKey is invalid
    BadPublicKeyInfo,
}

#[derive(Error, Debug, PartialEq, Clone)]
/// Errors that can occur when converting between certificate-related types
pub enum CertificateConversionError {
    #[error(transparent)]
    /// The constraints of the source or target types were met
    ConstraintError(#[from] ConstraintError),
    #[error(transparent)]
    /// The input was invalid - Either malformed or out of bounds
    InvalidInput(#[from] InvalidInput),
    #[error("Encountered DER encoding error")]
    /// An error occurred while parsing a DER encoded object
    DerError(der::Error),
    #[error("Encountered DER OID error")]
    /// An error occurred while parsing an OID
    ConstOidError(der::oid::Error),
    #[error("Critical extension cannot be converted")]
    /// A critical extension is unknown and cannot be converted
    UnknownCriticalExtension {
        /// The OID of the unknown extension
        oid: ObjectIdentifier,
    },
    #[error(transparent)]
    /// The source or target certificate is invalid
    InvalidCert(#[from] InvalidCert),
}
#[cfg(feature = "reqwest")]
#[derive(Error, Debug)]
/// Errors that can occur when making a request
pub enum RequestError {
    #[error(transparent)]
    /// Reqwest encountered an error
    HttpError(#[from] reqwest::Error),
    #[error("Failed to deserialize response into expected type")]
    /// The response could not be deserialized into the expected type
    DeserializationError(#[from] serde_json::Error),
    #[error("Failed to convert response into expected type")]
    /// The response could not be converted into the expected type
    ConversionError(#[from] CertificateConversionError),
    #[error(transparent)]
    /// The URL could not be parsed
    UrlError(#[from] url::ParseError),
    /// Received a status code that indicates something other than success.
    #[error("Received status code {:?}, expected any of {:?}", received, expected)]
    StatusCode {
        received: http::StatusCode,
        expected: Vec<http::StatusCode>,
    },
    #[error("{reason}")]
    Custom { reason: String },
}

impl From<InvalidInput> for RequestError {
    fn from(value: InvalidInput) -> Self {
        Self::Custom {
            reason: value.to_string(),
        }
    }
}

impl From<der::Error> for CertificateConversionError {
    fn from(value: der::Error) -> Self {
        Self::DerError(value)
    }
}

impl From<der::oid::Error> for CertificateConversionError {
    fn from(value: der::oid::Error) -> Self {
        Self::ConstOidError(value)
    }
}
