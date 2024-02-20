// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::{BitString, Ia5String, Uint};
use der::{Decode, Encode, Length};
use spki::{SubjectPublicKeyInfoOwned};



use x509_cert::name::Name;



use crate::key::{PrivateKey, PublicKey};
use crate::signature::{Signature};
use crate::{Constrained, Error, InvalidInput};

use super::{PkcsVersion, SessionId, SubjectPublicKeyInfo};

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
    inner_csr: IdCsrInner<S>,
    signature_algorithm: S::SignatureAlgorithm,
    signature: S,
}

impl<S: Signature> IdCsr<S> {
    /// Creates a new polyproto ID-Cert CSR, according to PKCS#10. The CSR is being signed using the
    /// subjects' supplied signing key ([PrivateKey])
    ///
    /// ## Arguments
    ///
    /// - **subject**: A [Name], comprised of:
    ///   - Common Name: The federation ID of the subject (actor)
    ///   - Domain Component: Actor home server subdomain, if applicable. May be repeated, depending
    ///                       on how many subdomain levels there are.
    ///   - Domain Component: Actor home server domain.
    ///   - Domain Component: Actor home server tld, if applicable.
    ///   - Organizational Unit: Optional. May be repeated.
    /// - **signing_key**: Subject signing key. Will NOT be included in the certificate. Is used to
    ///                    sign the CSR.
    /// - **subject_unique_id**: [Uint], subject (actor) session ID. MUST NOT exceed 32 characters
    ///                          in length.
    pub fn new(
        subject: Name,
        signing_key: impl PrivateKey<S>,
        subject_session_id: Ia5String,
    ) -> Result<IdCsr<S>, Error> {
        subject.validate()?;
        let inner_csr =
            IdCsrInner::<S>::new(subject, signing_key.pubkey(), subject_session_id.clone())?;

        let version_bytes = Uint::new(&[inner_csr.version as u8])?.to_der()?;
        let subject_bytes = inner_csr.subject.to_der()?;
        let spki_bytes =
            SubjectPublicKeyInfoOwned::from(inner_csr.subject_public_key_info.clone()).to_der()?;
        let session_id = SessionId::new(subject_session_id)?;
        let session_id_bytes = session_id.as_attribute().to_der()?;

        let mut to_sign = Vec::new();
        to_sign.extend(version_bytes);
        to_sign.extend(subject_bytes);
        to_sign.extend(spki_bytes);
        to_sign.extend(session_id_bytes);

        let signature = signing_key.sign(&to_sign);
        let signature_algorithm = signature.algorithm().clone();

        Ok(IdCsr {
            inner_csr,
            signature_algorithm,
            signature,
        })
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
    version: PkcsVersion,
    /// Information about the subject (actor).
    pub subject: Name,
    /// The subjects' public key and related metadata.
    pub subject_public_key_info: SubjectPublicKeyInfo<S::SignatureAlgorithm>,
    /// The session ID of the client. No two valid certificates may exist for one session ID.
    pub subject_session_id: Ia5String,
}

impl<S: Signature> IdCsrInner<S> {
    /// Creates a new [IdCsrInner].
    ///
    /// The length of `subject_session_id` MUST NOT exceed 32.
    pub fn new(
        subject: Name,
        public_key: &impl PublicKey<S>,
        subject_session_id: Ia5String,
    ) -> Result<IdCsrInner<S>, Error> {
        subject.validate()?;
        // Validate session_id constraints and create session ID [Attribute] from input
        // TODO: Make SessionID own struct?
        if subject_session_id.len() > Length::new(32) {
            return Err(InvalidInput::SessionIdTooLong.into());
        }

        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm: public_key.algorithm(),
            subject_public_key: BitString::from_der(&public_key.to_der()?)?,
        };

        Ok(IdCsrInner {
            version: PkcsVersion::V1,
            subject,
            subject_public_key_info,
            subject_session_id,
        })
    }
}
