// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::hash::Hash;
use std::str::FromStr;

use der::asn1::BitString;
use der::pem::LineEnding;
use der::{Decode, DecodePem, Encode, EncodePem};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence};

use crate::errors::CertificateConversionError;
use crate::types::der::asn1::Ia5String;
use crate::{Constrained, ConstraintError, OID_RDN_DOMAIN_COMPONENT, OID_RDN_UNIQUE_IDENTIFIER};

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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId {
    /// The session ID, represented as an [Ia5String].
    session_id: Ia5String,
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.session_id.fmt(f)
    }
}

impl SessionId {
    #[allow(clippy::new_ret_no_self)]
    /// Creates a new [SessionId] which can be converted into an [Attribute] using `.as_attribute()`,
    /// if needed. Checks if the input is a valid Ia5String and if the [SessionId] constraints have
    /// been violated.
    pub fn new_validated(id: &str) -> Result<Self, ConstraintError> {
        let ia5string = match der::asn1::Ia5String::new(id) {
            Ok(string) => string,
            Err(_) => {
                return Err(ConstraintError::Malformed(Some(
                    "Invalid Ia5String passed as SessionId".to_string(),
                )));
            }
        };

        let session_id = SessionId {
            session_id: ia5string.into(),
        };
        session_id.validate(None)?;
        Ok(session_id)
    }

    /// Converts this [SessionId] into a [Name] for use in a certificate.
    pub fn to_rdn_sequence(&self) -> Name {
        RdnSequence::from_str(&format!("uniqueIdentifier={self}")).unwrap()
    }

    /// Returns the inner [Ia5String] of this [SessionId] as an owned value.
    pub fn to_ia5string(&self) -> Ia5String {
        self.session_id.clone()
    }
}

impl From<SessionId> for Ia5String {
    fn from(value: SessionId) -> Self {
        value.session_id
    }
}

impl TryFrom<Ia5String> for SessionId {
    type Error = ConstraintError;

    fn try_from(value: Ia5String) -> Result<Self, Self::Error> {
        SessionId::new_validated(value.to_string().as_str())
    }
}

impl From<SessionId> for Name {
    fn from(value: SessionId) -> Self {
        value.to_rdn_sequence()
    }
}

impl TryFrom<AttributeTypeAndValue> for SessionId {
    type Error = ConstraintError;

    fn try_from(value: AttributeTypeAndValue) -> Result<Self, Self::Error> {
        if value.oid != OID_RDN_UNIQUE_IDENTIFIER {
            return Err(ConstraintError::Malformed(Some(format!(
                "Expected OID for uniqueIdentifier {OID_RDN_UNIQUE_IDENTIFIER}, found OID {}",
                value.oid
            ))));
        }
        let ia5string = Ia5String::new(value.value.value()).map_err(|e| {
            ConstraintError::Malformed(Some(format!(
                "Value found in uniqueIdentifier is not a valid Ia5String: {e}"
            )))
        })?;
        Self::try_from(ia5string)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Whether something is intended for an actor or a home server.
#[allow(missing_docs)]
pub enum Target {
    Actor,
    HomeServer,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
/// `PKCS#10` version. From the PKCS specification document (RFC 2986):
/// > version is the version number, for compatibility with future
/// > revisions of this document.  It shall be 0 for this version of
/// > the standard.
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

/// Information regarding a subjects' public key. This is a `SubjectPublicKeyInfo` in the context of
/// PKCS #10.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKeyInfo {
    /// Properties of the signature algorithm used to create the public key.
    pub algorithm: AlgorithmIdentifierOwned,
    /// The public key, represented as a [BitString].
    pub public_key_bitstring: BitString,
}

impl PublicKeyInfo {
    /// Create a new [PublicKeyInfo] from the provided DER encoded data. The data must be a valid,
    /// DER encoded PKCS #10 `SubjectPublicKeyInfo` structure. The caller is responsible for
    /// verifying the correctness of the resulting data before using it.
    pub fn from_der(value: &str) -> Result<Self, CertificateConversionError> {
        Ok(SubjectPublicKeyInfoOwned::from_der(value.as_bytes())?.into())
    }

    /// Create a new [PublicKeyInfo] from the provided PEM encoded data. The data must be a valid,
    /// PEM encoded PKCS #10 `SubjectPublicKeyInfo` structure. The caller is responsible for
    /// verifying the correctness of the resulting data before using it.
    pub fn from_pem(value: &str) -> Result<Self, CertificateConversionError> {
        Ok(SubjectPublicKeyInfoOwned::from_pem(value.as_bytes())?.into())
    }

    /// Encode this type as DER, returning a byte vector.
    pub fn to_der(&self) -> Result<Vec<u8>, CertificateConversionError> {
        Ok(SubjectPublicKeyInfoOwned::from(self.clone()).to_der()?)
    }

    /// Encode this type as PEM, returning a string.
    pub fn to_pem(&self, line_ending: LineEnding) -> Result<String, CertificateConversionError> {
        Ok(SubjectPublicKeyInfoOwned::from(self.clone()).to_pem(line_ending)?)
    }
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

/// Checks, if the domain components of two [Name]s are equal and ordered in the same way. Returns
/// `true`, if the domain components are equal, `false` otherwise.
pub fn equal_domain_components(name_1: &Name, name_2: &Name) -> bool {
    let mut domain_components_1 = Vec::new();
    let mut domain_components_2 = Vec::new();
    for rdn in name_1.0.iter() {
        for ava in rdn.0.iter() {
            if ava.oid == OID_RDN_DOMAIN_COMPONENT {
                domain_components_1.push(String::from_utf8_lossy(ava.value.value()));
            }
        }
    }
    for rdn in name_2.0.iter() {
        for ava in rdn.0.iter() {
            if ava.oid == OID_RDN_DOMAIN_COMPONENT {
                domain_components_2.push(String::from_utf8_lossy(ava.value.value()));
            }
        }
    }
    domain_components_1 == domain_components_2
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use x509_cert::name::RdnSequence;

    use super::*;
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_equal_domain_components_eq() {
        #[allow(clippy::unwrap_used)]
        let rdn_1 = RdnSequence::from_str(
            "CN=root,OU=programmer,DC=www,DC=polyphony,DC=chat,UID=root@polyphony.chat,uniqueIdentifier=root",
        )
        .unwrap();

        #[allow(clippy::unwrap_used)]
        let rdn_2 = RdnSequence::from_str(
            "CN=user1,DC=www,DC=polyphony,DC=chat,UID=user1@polyphony.chat,uniqueIdentifier=user1",
        )
        .unwrap();
        assert!(equal_domain_components(&rdn_1, &rdn_2));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_equal_domain_components_ne() {
        #[allow(clippy::unwrap_used)]
        let rdn_1 = RdnSequence::from_str(
            "CN=root,OU=programmer,DC=www,DC=polyphony,DC=chat,UID=root@polyphony.chat,uniqueIdentifier=root",
        )
        .unwrap();

        #[allow(clippy::unwrap_used)]
        let rdn_2 = RdnSequence::from_str(
            "CN=user1,DC=proto,DC=polyphony,DC=chat,UID=user1@polyphony.chat,uniqueIdentifier=user1",
        )
        .unwrap();
        assert!(!equal_domain_components(&rdn_1, &rdn_2));
    }
}
