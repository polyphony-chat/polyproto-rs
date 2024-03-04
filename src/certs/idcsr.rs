// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::marker::PhantomData;

use der::asn1::{BitString, SetOfVec, Uint};
use der::{Decode, Encode};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::Attributes;
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo};

use crate::key::{PrivateKey, PublicKey};
use crate::signature::Signature;
use crate::{Constrained, Error};

use super::{PkcsVersion, PublicKeyInfo, SessionId};

#[derive(Debug, Clone, PartialEq, Eq)]
/// A polyproto Certificate Signing Request, compatible with [IETF RFC 2986 "PKCS #10"](https://datatracker.ietf.org/doc/html/rfc2986).
/// Can be exchanged for an [IdCert] by requesting one from a certificate authority in exchange
/// for this [IdCsr].
///
/// In the context of PKCS #10, this is a `CertificationRequest`:
///
/// ```md
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo CertificationRequestInfo,
///     signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
///     signature          BIT STRING
/// }
/// ```
pub struct IdCsr<S: Signature> {
    pub inner_csr: IdCsrInner<S>,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: S,
}

impl<S: Signature> IdCsr<S> {
    /// Performs basic input validation and creates a new polyproto ID-Cert CSR, according to
    /// PKCS#10. The CSR is being signed using the subjects' supplied signing key ([PrivateKey])
    ///
    /// ## Arguments
    ///
    /// - **subject**: A [Name], comprised of:
    ///   - Common Name: The federation ID of the subject (actor)
    ///   - Domain Component: Actor home server subdomain, if applicable. May be repeated, depending
    ///                       on how many subdomain levels there are.
    ///   - Domain Component: Actor home server domain.
    ///   - Domain Component: Actor home server TLD, if applicable.
    ///   - Organizational Unit: Optional. May be repeated.
    /// - **signing_key**: Subject signing key. Will NOT be included in the certificate. Is used to
    ///                    sign the CSR.
    /// - **subject_unique_id**: [Uint], subject (actor) session ID. MUST NOT exceed 32 characters
    ///                          in length.
    pub fn new(
        subject: &Name,
        signing_key: &impl PrivateKey<S>,
        attributes: &Attributes,
    ) -> Result<IdCsr<S>, Error> {
        subject.validate()?;
        let inner_csr = IdCsrInner::<S>::new(subject, signing_key.pubkey(), attributes)?;
        let cert_req_info = CertReqInfo::from(inner_csr);
        let signature = signing_key.sign(&cert_req_info.to_der()?);
        let inner_csr = IdCsrInner::<S>::try_from(cert_req_info)?;

        let signature_algorithm = S::algorithm_identifier();

        Ok(IdCsr {
            inner_csr,
            signature_algorithm,
            signature,
        })
    }

    pub fn valid_actor_csr(&self) -> Result<(), Error> {
        self.inner_csr.subject.validate()?;
        todo!()
    }

    pub fn valid_home_server_csr(&self) -> Result<(), Error> {
        self.inner_csr.subject.validate()?;
        todo!()
    }
}

/// In the context of PKCS #10, this is a `CertificationRequestInfo`:
///
/// ```md
/// CertificationRequestInfo ::= SEQUENCE {
///     version       INTEGER { v1(0) } (v1,...),
///     subject       Name,
///     subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
///     attributes    [0] Attributes{{ CRIAttributes }}
/// }
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IdCsrInner<S: Signature> {
    /// `PKCS#10` version. Default: 0 for `PKCS#10` v1
    pub version: PkcsVersion,
    /// Information about the subject (actor).
    pub subject: Name,
    /// The subjects' public key and related metadata.
    pub subject_public_key_info: PublicKeyInfo,
    /// attributes is a collection of attributes providing additional
    /// information about the subject of the certificate.
    pub attributes: Attributes,
    phantom_data: PhantomData<S>,
}

// TODO: Problem: SubjectPublicKeyInfo only stores the BitString of a PublicKey. This is not good,
// because we cannot use the PublicKey trait and its verify() method to verify that the signature
// in a given IdCsr matches the PublicKey presented in the IdCsrInner.

impl<S: Signature> IdCsrInner<S> {
    /// Creates a new [IdCsrInner].
    ///
    /// The length of `subject_session_id` MUST NOT exceed 32.
    pub fn new(
        subject: &Name,
        public_key: &impl PublicKey<S>,
        attributes: &Attributes,
    ) -> Result<IdCsrInner<S>, Error> {
        subject.validate()?;

        let subject_public_key_info = PublicKeyInfo {
            algorithm: public_key.public_key_info().algorithm,
            public_key_bitstring: BitString::from_der(
                &public_key.public_key_info().public_key_bitstring.to_der()?,
            )?,
        };

        let subject = subject.clone();
        let attributes = attributes.clone();

        Ok(IdCsrInner {
            version: PkcsVersion::V1,
            subject,
            subject_public_key_info,
            attributes,
            phantom_data: PhantomData,
        })
    }
}

impl<S: Signature> TryFrom<CertReq> for IdCsr<S> {
    type Error = Error;

    fn try_from(value: CertReq) -> Result<Self, Error> {
        Ok(IdCsr {
            inner_csr: IdCsrInner::try_from(value.info)?,
            signature_algorithm: value.algorithm,
            // TODO: raw_bytes() or as_bytes()?
            signature: S::from_bitstring(value.signature.raw_bytes()),
        })
    }
}

impl<S: Signature> TryFrom<CertReqInfo> for IdCsrInner<S> {
    type Error = Error;

    fn try_from(value: CertReqInfo) -> Result<Self, Self::Error> {
        let rdn_sequence = value.subject;
        rdn_sequence.validate()?;
        let public_key = PublicKeyInfo {
            algorithm: value.public_key.algorithm,
            public_key_bitstring: value.public_key.subject_public_key,
        };

        Ok(IdCsrInner {
            version: PkcsVersion::V1,
            subject: rdn_sequence,
            subject_public_key_info: public_key,
            attributes: value.attributes,
            phantom_data: PhantomData,
        })
    }
}

impl<S: Signature> TryFrom<IdCsr<S>> for CertReq {
    type Error = Error;

    fn try_from(value: IdCsr<S>) -> Result<Self, Self::Error> {
        Ok(CertReq {
            info: value.inner_csr.into(),
            algorithm: value.signature_algorithm,
            signature: value.signature.to_bitstring()?,
        })
    }
}

impl<S: Signature> From<IdCsrInner<S>> for CertReqInfo {
    fn from(value: IdCsrInner<S>) -> Self {
        CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: value.subject,
            public_key: value.subject_public_key_info.into(),
            attributes: SetOfVec::new(),
        }
    }
}
