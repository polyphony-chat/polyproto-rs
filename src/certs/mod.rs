// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::{Any, BitString, Ia5String, SetOfVec};
use der::{Decode, Encode};
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::attr::Attribute;

use crate::{Constrained, Error};

/// Complete, signed [IdCert]
pub mod idcert;
/// [IdCertTbs] is an [IdCert] which has not yet been signed by
pub mod idcerttbs;
/// Certificate Signing Request for an [IdCert]/[IdCertTbs]
pub mod idcsr;

/// Custom "SessionId" [Attribute] for use in polyproto.
/// DOCUMENTME: Add notes about what session_ids are in polyproto.
/// DOCUMENTME: Add ASN.1 notation for this Attribute
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId {
    attribute: Attribute,
    session_id: Ia5String,
}

impl SessionId {
    #[allow(clippy::new_ret_no_self)]
    /// Creates a new [SessionId] which can be converted into an [Attribute] using `.as_attribute()`,
    /// if needed.
    pub fn new(id: Ia5String) -> Result<Self, Error> {
        let mut set_of_vec = SetOfVec::new();
        let any = Any::from_der(&id.to_der()?)?;
        set_of_vec.insert(any)?;
        let session_id_attribute = Attribute {
                oid: ObjectIdentifier::new("1.3.6.1.4.1.987654321.1.1").expect("The object identifier specified is not in correct OID notation. Please file a bug report under https://github.com/polyphony-chat/polyproto"),
                values: set_of_vec
            };
        let session_id = Self {
            attribute: session_id_attribute,
            session_id: id,
        };
        session_id.validate()?;
        Ok(session_id)
    }
}

impl SessionId {
    /// Returns the inner [Attribute] field
    pub fn as_attribute(&self) -> &Attribute {
        &self.attribute
    }

    /// Returns the inner `session_id` field
    pub fn as_ia5string(&self) -> &Ia5String {
        &self.session_id
    }
}

impl From<SessionId> for Attribute {
    fn from(value: SessionId) -> Self {
        value.attribute
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
pub struct SubjectPublicKeyInfo {
    /// Properties of the signature algorithm used to create the public key.
    pub algorithm: AlgorithmIdentifierOwned,
    /// The public key, represented as a [BitString].
    pub subject_public_key: BitString,
}

impl From<SubjectPublicKeyInfoOwned> for SubjectPublicKeyInfo {
    fn from(value: SubjectPublicKeyInfoOwned) -> Self {
        SubjectPublicKeyInfo {
            algorithm: value.algorithm,
            subject_public_key: value.subject_public_key,
        }
    }
}

impl From<SubjectPublicKeyInfo> for SubjectPublicKeyInfoOwned {
    fn from(value: SubjectPublicKeyInfo) -> Self {
        SubjectPublicKeyInfoOwned {
            algorithm: value.algorithm,
            subject_public_key: value.subject_public_key,
        }
    }
}
