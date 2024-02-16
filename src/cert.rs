// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::{BitString, Uint};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{Profile, TbsCertificateInner};
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::signature::{Signature, SignatureAlgorithm};
use crate::{IdCertToTbsCert, TbsCertToIdCert};

/// A signed polyproto ID-Cert, consisting of the actual certificate, the CA-generated signature and
/// metadata about that signature.
///
/// ID-Certs are valid subset of X.509 v3 certificates. The limitations are documented in the
/// polyproto specification.
#[derive(Debug)]
pub struct IdCert<S: Signature, T: SignatureAlgorithm> {
    /// Inner TBS (To be signed) certificate
    pub tbs_certificate: IdCertTbs<T>,
    /// Signature for the TBS certificate
    pub signature: S,
}

// TODO: T, S: SignatureAlgorithm
// Maybe trait with associated types?

/// An unsigned polyproto ID-Cert.
///
/// ID-Certs are generally more restrictive than general-use X.509-certificates, hence why a
/// conversion between those two types can fail.
///
/// ## Compatibility
///
/// This crate aims to be compatible with [`x509_cert`], to take advantage of the already existing
/// typedefs and functionality for creating and verifying X.509 certificates, provided by that
/// crate.
///
/// `IdCertTbs` implements `TryFrom<[TbsCertificateInner]<P>>`, where `TbsCertificateInner` is
/// [`x509_cert::certificate::TbsCertificateInner`]. This crate also provides an implementation for
/// `TryFrom<IdCertTbs<T>> for TbsCertificateInner<P>`.
#[derive(Debug)]
pub struct IdCertTbs<T: SignatureAlgorithm> {
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
    pub subject_public_key_info: SubjectPublicKeyInfo<T>,
    /// [`BitString`] representing the federation ID of the actor, as defined in the polyproto
    /// specification document.
    pub subject_unique_id: BitString,
    /// X.509 Extensions matching what is described in the polyproto specification document.
    pub extensions: Extensions,
}

/// Information regarding a subjects' public key.
#[derive(Debug)]
pub struct SubjectPublicKeyInfo<T: SignatureAlgorithm> {
    /// Properties of the signature algorithm used to create the public key.
    pub algorithm: T,
    /// The public key, represented as a [`BitString`].
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
// - Add ::new() method to IdCertTbs
// - Add ::sign() method to IdCertTbs, yielding an IdCert
// - If CA, check for path length etc.

impl<T: SignatureAlgorithm, P: Profile> TryFrom<TbsCertificateInner<P>> for IdCertTbs<T> {
    type Error = TbsCertToIdCert;

    fn try_from(value: TbsCertificateInner<P>) -> Result<Self, Self::Error> {
        let subject_unique_id = match value.subject_unique_id {
            Some(suid) => suid,
            None => return Err(TbsCertToIdCert::SubjectUid),
        };

        let extensions = match value.extensions {
            Some(ext) => ext,
            None => return Err(TbsCertToIdCert::Extensions),
        };

        let subject_public_key_info =
            SubjectPublicKeyInfo::<T>::from(value.subject_public_key_info);

        let serial_number = match Uint::new(value.serial_number.as_bytes()) {
            Ok(snum) => snum,
            Err(e) => return Err(TbsCertToIdCert::Signature(e)),
        };

        Ok(IdCertTbs {
            serial_number,
            signature_algorithm: value.signature.into(),
            issuer: value.issuer,
            validity: value.validity,
            subject: value.subject,
            subject_public_key_info,
            subject_unique_id,
            extensions,
        })
    }
}

impl<T: SignatureAlgorithm, P: Profile> TryFrom<IdCertTbs<T>> for TbsCertificateInner<P> {
    type Error = IdCertToTbsCert;

    fn try_from(value: IdCertTbs<T>) -> Result<Self, Self::Error> {
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
            subject_unique_id: Some(value.subject_unique_id),
            extensions: Some(value.extensions),
        })
    }
}
