// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use der::asn1::{BitString, Ia5String};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::{Constrained, ConstraintError};

/// Additional capabilities ([x509_cert::ext::Extensions] or [x509_cert::attr::Attributes], depending
/// on the context) of X.509 certificates.
pub mod capabilities;
/// Complete, signed [IdCert]
pub mod idcert;
/// [IdCertTbs] is an [IdCert] which has not yet been signed by
pub mod idcerttbs;
/// Certificate Signing Request for an [IdCert]/[IdCertTbs]
pub mod idcsr;

/// polyproto client Session ID. Must be unique for each client. Must be between 1 and =32
/// characters in length. The session ID is used to uniquely identify a client in the context of
/// polyproto. Client certificates will change over time, but the session ID of a particular client
/// will remain the same.
///
/// [Constrained] is implemented for this type, meaning it can be validated using `.validate()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId {
    /// The session ID, represented as an [Ia5String].
    session_id: Ia5String,
}

impl Deref for SessionId {
    type Target = Ia5String;

    fn deref(&self) -> &Self::Target {
        &self.session_id
    }
}

impl DerefMut for SessionId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session_id
    }
}

impl SessionId {
    #[allow(clippy::new_ret_no_self)]
    /// Creates a new [SessionId] which can be converted into an [Attribute] using `.as_attribute()`,
    /// if needed. Checks if the input is a valid Ia5String and if the [SessionId] constraints have
    /// been violated.
    pub fn new_validated(id: String) -> Result<Self, ConstraintError> {
        let ia5string = Ia5String::new(&id);
        if let Ok(converted) = ia5string {
            let session_id = Self {
                session_id: converted,
            };
            session_id.validate()?;
            Ok(session_id)
        } else {
            Err(ConstraintError::Malformed(Some(
                "Cannot turn input String into Ia5String".to_string(),
            )))
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
/// `PKCS#10` version. From the PKCS specification document (RFC 2986):
/// > version is the version number, for compatibility with future
/// revisions of this document.  It shall be 0 for this version of
/// the standard.
///
/// The specification also says:
/// > `version       INTEGER { v1(0) } (v1,...),`
///
/// Version "v1" corresponds to enum variant `V1`, which is represented as the `u8`
/// integer zero (0).
pub enum PkcsVersion {
    #[default]
    /// Version 1 (0) of the PKCS#10 specification implementation
    V1 = 0,
}

/// Information regarding a subjects' public key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKeyInfo {
    /// Properties of the signature algorithm used to create the public key.
    pub algorithm: AlgorithmIdentifierOwned,
    /// The public key, represented as a [BitString].
    pub public_key_bitstring: BitString,
}

impl From<SubjectPublicKeyInfoOwned> for PublicKeyInfo {
    fn from(value: SubjectPublicKeyInfoOwned) -> Self {
        PublicKeyInfo {
            algorithm: value.algorithm,
            public_key_bitstring: value.subject_public_key,
        }
    }
}

impl From<PublicKeyInfo> for SubjectPublicKeyInfoOwned {
    fn from(value: PublicKeyInfo) -> Self {
        SubjectPublicKeyInfoOwned {
            algorithm: value.algorithm,
            subject_public_key: value.public_key_bitstring,
        }
    }
}
