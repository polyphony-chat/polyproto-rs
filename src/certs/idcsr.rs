// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::marker::PhantomData;

use der::asn1::{BitString, Uint};
use der::{Decode, Encode, Length};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::name::Name;

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
        subject: Name,
        signing_key: impl PrivateKey<S>,
        subject_session_id: SessionId,
    ) -> Result<IdCsr<S>, Error> {
        subject.validate()?;
        subject_session_id.validate()?;
        let inner_csr =
            IdCsrInner::<S>::new(subject, signing_key.pubkey(), subject_session_id.clone())?;

        let version_bytes = Uint::new(&[inner_csr.version as u8])?.to_der()?;
        let subject_bytes = inner_csr.subject.to_der()?;
        let spki_bytes =
            SubjectPublicKeyInfoOwned::from(inner_csr.subject_public_key_info.clone()).to_der()?;
        let session_id_bytes = subject_session_id.as_attribute().to_der()?;

        let mut to_sign = Vec::new();
        to_sign.extend(version_bytes);
        to_sign.extend(subject_bytes);
        to_sign.extend(spki_bytes);
        to_sign.extend(session_id_bytes);

        let signature = signing_key.sign(&to_sign);
        let signature_algorithm = S::algorithm_identifier();

        Ok(IdCsr {
            inner_csr,
            signature_algorithm,
            signature,
        })
    }

    pub fn valid_actor_csr(&self) -> Result<(), Error> {
        self.inner_csr.subject.validate()?;
        self.inner_csr.subject_session_id.validate()?;
        todo!()
    }

    pub fn valid_home_server_csr(&self) -> Result<(), Error> {
        self.inner_csr.subject.validate()?;
        self.inner_csr.subject_session_id.validate()?;
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
    /// The session ID of the client. No two valid certificates may exist for one session ID.
    pub subject_session_id: SessionId,
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
        subject: Name,
        public_key: &impl PublicKey<S>,
        subject_session_id: SessionId,
    ) -> Result<IdCsrInner<S>, Error> {
        subject.validate()?;

        let subject_public_key_info = PublicKeyInfo {
            algorithm: public_key.public_key_info().algorithm,
            public_key_bitstring: BitString::from_der(
                &public_key.public_key_info().public_key_bitstring.to_der()?,
            )?,
        };

        Ok(IdCsrInner {
            version: PkcsVersion::V1,
            subject,
            subject_public_key_info,
            subject_session_id,
            phantom_data: PhantomData,
        })
    }
}

impl<S: Signature> Encode for IdCsrInner<S> {
    // TODO: Test this
    fn encoded_len(&self) -> der::Result<Length> {
        let len_version = Uint::new(&[self.version as u8])?.encoded_len()?;
        let len_subject = self.subject.encoded_len()?;
        let spki_converted: SubjectPublicKeyInfoOwned = self.subject_public_key_info.clone().into();
        let len_spki = spki_converted.encoded_len()?;
        let len_ssid = self.subject_session_id.as_attribute().encoded_len()?;
        len_spki + len_subject + len_ssid + len_version
    }

    // TODO: Test this
    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let uint_version = Uint::new(&[self.version as u8])?;
        let spki_converted: SubjectPublicKeyInfoOwned = self.subject_public_key_info.clone().into();
        uint_version.encode(encoder)?;
        self.subject.encode(encoder)?;
        spki_converted.encode(encoder)?;
        self.subject_session_id.as_attribute().encode(encoder)?;
        Ok(())
    }
}

impl<S: Signature> Encode for IdCsr<S> {
    // TODO: Test this
    fn encoded_len(&self) -> der::Result<Length> {
        let len_inner = self.inner_csr.encoded_len()?;
        let len_signature_algorithm = AlgorithmIdentifierOwned {
            oid: self.signature_algorithm.oid,
            parameters: self.signature_algorithm.parameters.clone(),
        }
        .encoded_len()?;
        let len_signature = self.signature.to_bitstring()?.encoded_len()?;
        len_inner + len_signature_algorithm + len_signature
    }

    // TODO: Test this
    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.inner_csr.encode(encoder)?;
        self.signature_algorithm.clone().encode(encoder)?;
        self.signature.to_bitstring()?.encode(encoder)?;
        Ok(())
    }
}

//TODO: Implement decode trait
