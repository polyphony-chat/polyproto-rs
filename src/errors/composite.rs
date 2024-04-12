// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use thiserror::Error;

use super::base::{ConstraintError, InvalidInput};

/// Error type covering possible failures when converting a [x509_cert::TbsCertificate]
/// to a [crate::cert::IdCertTbs]
#[derive(Error, Debug, PartialEq, Clone)]
pub enum TbsCertToIdCert {
    #[error("field 'subject_unique_id' was None. Expected: Some(der::asn1::BitString)")]
    SubjectUid,
    #[error("field 'extensions' was None. Expected: Some(x509_cert::ext::Extensions)")]
    Extensions,
    #[error("Supplied integer too long")]
    Signature(der::Error),
    #[error(transparent)]
    ConstraintError(#[from] ConstraintError),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInput),
}

/// Error type covering possible failures when converting a [crate::cert::IdCertTbs]
/// to a [x509_cert::TbsCertificate]
#[derive(Error, Debug, PartialEq, Clone)]
pub enum IdCertToTbsCert {
    #[error("Serial number could not be converted")]
    SerialNumber(der::Error),
    #[error(transparent)]
    ConstraintError(#[from] ConstraintError),
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum InvalidCert {
    #[error("The signature does not match the contents of the certificate")]
    InvalidSignature,
    #[error("The subject presented on the certificate is malformed or otherwise invalid")]
    InvalidSubject(ConstraintError),
    #[error("The issuer presented on the certificate is malformed or otherwise invalid")]
    InvalidIssuer(ConstraintError),
    #[error("The validity period of the certificate is invalid, or the certificate is expired")]
    InvalidValidity,
    #[error("The capabilities presented on the certificate are invalid or otherwise malformed")]
    InvalidCapabilities(ConstraintError),
}

impl From<der::Error> for InvalidInput {
    fn from(value: der::Error) -> Self {
        Self::DerError(value)
    }
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum CertReqToIdCsr {
    #[error(transparent)]
    CertReqInfoToIdCsrInner(#[from] CertReqInfoError),
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum CertReqInfoError {
    #[error(transparent)]
    ConstraintError(#[from] ConstraintError),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInput),
    #[error("Couldn't parse CertReqInfo from provided DER bytes")]
    DerError(der::Error),
    #[error(transparent)]
    MalformedIdCsrInner(#[from] IdCsrInnerError),
}

impl From<der::Error> for CertReqInfoError {
    fn from(value: der::Error) -> Self {
        Self::DerError(value)
    }
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum IdCsrError {
    #[error("The Bitstring is invalid")]
    InvalidBitstring(der::Error),
    #[error(transparent)]
    IdCsrInnerToCertReqInfo(#[from] IdCsrInnerError),
    #[error(transparent)]
    ConstraintError(#[from] ConstraintError),
}

impl From<der::Error> for IdCsrError {
    fn from(value: der::Error) -> Self {
        Self::InvalidBitstring(value)
    }
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum IdCsrInnerError {
    #[error(transparent)]
    ConstraintError(#[from] ConstraintError),
    #[error("Encountered DER encoding error")]
    DerError(der::Error),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInput),
}

impl From<der::Error> for IdCsrInnerError {
    fn from(value: der::Error) -> Self {
        Self::DerError(value)
    }
}

#[derive(Error, Debug, PartialEq, Hash, Clone)]
pub enum PublicKeyError {
    #[error("The signature does not match the data")]
    BadSignature,
    #[error("The provided PublicKeyInfo could not be made into a PublicKey")]
    BadPublicKeyInfo,
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum IdCertTbsError {
    #[error(transparent)]
    PublicKeyError(#[from] PublicKeyError),
    #[error(transparent)]
    ConstraintError(#[from] ConstraintError),
    #[error(transparent)]
    IdCsrInnerError(#[from] IdCsrInnerError),
}
