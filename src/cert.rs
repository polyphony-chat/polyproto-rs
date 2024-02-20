// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::{Any, BitString, SetOfVec, Uint};
use der::{Decode, Encode, Length};
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::attr::Attribute;
use x509_cert::certificate::{Profile, TbsCertificateInner};
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::key::{PrivateKey, PublicKey};
use crate::signature::{Signature, SignatureAlgorithm};
use crate::{Constrained, Error, IdCertToTbsCert, InvalidInput, TbsCertToIdCert};

/// A signed polyproto ID-Cert, consisting of the actual certificate, the CA-generated signature and
/// metadata about that signature.
///
/// ID-Certs are valid subset of X.509 v3 certificates. The limitations are documented in the
/// polyproto specification.
///
/// ## Generic Parameters
///
/// - **S**: The [Signature] and - by extension - [SignatureAlgorithm] this certificate was
///   signed with.
/// - **T**: The [SignatureAlgorithm] of the subjects' public key within the [IdCertTbs]
#[derive(Debug, PartialEq, Eq)]
pub struct IdCert<S: Signature, T: SignatureAlgorithm> {
    /// Inner TBS (To be signed) certificate
    pub tbs_certificate: IdCertTbs<S::SignatureAlgorithm, T>,
    /// Signature for the TBS certificate
    pub signature: S,
}

/// An unsigned polyproto ID-Cert.
///
/// ID-Certs are generally more restrictive than general-use X.509-certificates, hence why a
/// conversion between those two types can fail.
///
/// There are generally two ways to obtain an [IdCertTbs]:
/// 1. Creating a self-signed certificate, when the certificate holder is supposed to be a
///    certificate authority.
/// 2. Exchanging an [IdCsr] for an [IdCertTbs] as part of an [IdCert], when the certificate holder
///    is supposed to be an actor.
///
/// ## Compatibility
///
/// This crate aims to be compatible with [x509_cert] in order to utilize the existing
/// typedefs and functionality for creating and verifying X.509 certificates provided by that
/// crate.
///
/// `IdCertTbs` implements `TryFrom<[TbsCertificateInner]<P>>`, where `TbsCertificateInner` is
/// [x509_cert::certificate::TbsCertificateInner]. This crate also provides an implementation for
/// `TryFrom<IdCertTbs<T>> for TbsCertificateInner<P>`.
#[derive(Debug, PartialEq, Eq)]
pub struct IdCertTbs<T: SignatureAlgorithm, K: SignatureAlgorithm> {
    /// The certificates' serial number, as issued by the Certificate Authority.
    pub serial_number: Uint,
    /// The signature algorithm used by the Certificate Authority to sign this certificate.
    /// Must be equal to `T` in `IdCert<S: Signature, T: SignatureAlgorithm>`.
    pub signature_algorithm: T,
    /// X.501 name, identifying the issuer of the certificate.
    pub issuer: Name,
    /// Validity period of this certificate
    pub validity: Validity,
    /// X.501 name, identifying the subject (actor) of the certificate.
    pub subject: Name,
    /// Information regarding the subjects' public key.
    pub subject_public_key_info: SubjectPublicKeyInfo<K>,
    /// The session ID of the client. No two valid certificates may exist for one session ID.
    pub subject_session_id: BitString,
    /// X.509 Extensions matching what is described in the polyproto specification document.
    pub extensions: Extensions,
}

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
        subject_session_id: Uint,
    ) -> Result<IdCsr<S>, Error> {
        subject.validate()?;
        let inner_csr = IdCsrInner::<S>::new(subject, signing_key.pubkey(), subject_session_id)?;

        let version_bytes = Uint::new(&[inner_csr.version as u8])?.to_der()?;
        let subject_bytes = inner_csr.subject.to_der()?;
        let spki_bytes =
            SubjectPublicKeyInfoOwned::from(inner_csr.subject_public_key_info.clone()).to_der()?;
        let mut set_of_vec = SetOfVec::new();
        let any = Any::from_der(&inner_csr.subject_session_id.to_der()?)?; // 1.4
        set_of_vec.insert(any)?;
        let session_id_attribute = Attribute {
                oid: ObjectIdentifier::new("1.3.6.1.4.1.987654321.1.1").expect("The object identifier specified is not in correct OID notation. Please file a bug report under https://github.com/polyphony-chat/polyproto"),
                values: set_of_vec
            };
        let attribute_bytes = session_id_attribute.to_der()?;

        let mut to_sign = Vec::new();
        to_sign.extend(version_bytes);
        to_sign.extend(subject_bytes);
        to_sign.extend(spki_bytes);
        to_sign.extend(attribute_bytes);

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
    pub subject_session_id: Uint,
}

impl<S: Signature> IdCsrInner<S> {
    /// Creates a new [IdCsrInner].
    ///
    /// The length of `subject_session_id` MUST NOT exceed 32.
    pub fn new(
        subject: Name,
        public_key: &impl PublicKey<S>,
        subject_session_id: Uint,
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
pub struct SubjectPublicKeyInfo<T: SignatureAlgorithm> {
    /// Properties of the signature algorithm used to create the public key.
    pub algorithm: T,
    /// The public key, represented as a [BitString].
    pub subject_public_key: BitString,
}

impl<T: SignatureAlgorithm> From<SubjectPublicKeyInfoOwned> for SubjectPublicKeyInfo<T> {
    fn from(value: SubjectPublicKeyInfoOwned) -> Self {
        SubjectPublicKeyInfo {
            algorithm: value.algorithm.into(),
            subject_public_key: value.subject_public_key,
        }
    }
}

impl<T: SignatureAlgorithm> From<SubjectPublicKeyInfo<T>> for SubjectPublicKeyInfoOwned {
    fn from(value: SubjectPublicKeyInfo<T>) -> Self {
        let algorithm = AlgorithmIdentifierOwned {
            oid: value.algorithm.oid(),
            parameters: value.algorithm.parameters(),
        };

        SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key: value.subject_public_key,
        }
    }
}

// TODO: Check for bounds required by polyproto.
// - If CA, check for path length etc.
// TODO: Add ::new() method to IdCertTbs
// TODO: Add ::sign() method to IdCertTbs, yielding an IdCert

impl<T: SignatureAlgorithm, K: SignatureAlgorithm, P: Profile> TryFrom<TbsCertificateInner<P>>
    for IdCertTbs<T, K>
{
    type Error = Error;

    fn try_from(value: TbsCertificateInner<P>) -> Result<Self, Self::Error> {
        value.subject.validate()?;
        let subject_unique_id = match value.subject_unique_id {
            Some(suid) => suid,
            None => return Err(TbsCertToIdCert::SubjectUid.into()),
        };

        let extensions = match value.extensions {
            Some(ext) => ext,
            None => return Err(TbsCertToIdCert::Extensions.into()),
        };

        let subject_public_key_info =
            SubjectPublicKeyInfo::<K>::from(value.subject_public_key_info);

        let serial_number = match Uint::new(value.serial_number.as_bytes()) {
            Ok(snum) => snum,
            Err(e) => return Err(TbsCertToIdCert::Signature(e).into()),
        };

        Ok(IdCertTbs {
            serial_number,
            signature_algorithm: value.signature.into(),
            issuer: value.issuer,
            validity: value.validity,
            subject: value.subject,
            subject_public_key_info,
            subject_session_id: subject_unique_id,
            extensions,
        })
    }
}

impl<T: SignatureAlgorithm, K: SignatureAlgorithm, P: Profile> TryFrom<IdCertTbs<T, K>>
    for TbsCertificateInner<P>
{
    type Error = IdCertToTbsCert;

    fn try_from(value: IdCertTbs<T, K>) -> Result<Self, Self::Error> {
        let serial_number = match SerialNumber::<P>::new(value.serial_number.as_bytes()) {
            Ok(sernum) => sernum,
            Err(e) => return Err(IdCertToTbsCert::SerialNumber(e)),
        };

        let signature = AlgorithmIdentifierOwned {
            oid: value.signature_algorithm.oid(),
            parameters: value.signature_algorithm.parameters(),
        };

        Ok(TbsCertificateInner {
            version: x509_cert::Version::V3,
            serial_number,
            signature,
            issuer: value.issuer,
            validity: value.validity,
            subject: value.subject,
            subject_public_key_info: value.subject_public_key_info.into(),
            issuer_unique_id: None,
            subject_unique_id: Some(value.subject_session_id),
            extensions: Some(value.extensions),
        })
    }
}
