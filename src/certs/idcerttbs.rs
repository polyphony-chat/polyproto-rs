// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::Uint;
use spki::AlgorithmIdentifierOwned;
use x509_cert::certificate::{Profile, TbsCertificateInner};
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::errors::base::{ConstraintError, InvalidInput};
use crate::errors::composite::{IdCertToTbsCert, TbsCertToIdCert};
use crate::signature::Signature;
use crate::Constrained;

use super::capabilities::Capabilities;
use super::idcsr::IdCsr;
use super::PublicKeyInfo;

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
pub struct IdCertTbs {
    /// The certificates' serial number, as issued by the Certificate Authority.
    pub serial_number: Uint,
    /// The signature algorithm used by the Certificate Authority to sign this certificate.
    pub signature_algorithm: AlgorithmIdentifierOwned,
    /// X.501 name, identifying the issuer of the certificate.
    pub issuer: Name,
    /// Validity period of this certificate
    pub validity: Validity,
    /// X.501 name, identifying the subject (actor) of the certificate.
    pub subject: Name,
    /// Information regarding the subjects' public key.
    pub subject_public_key_info: PublicKeyInfo,
    /// X.509 Extensions matching what is described in the polyproto specification document.
    pub capabilities: Capabilities,
}

impl IdCertTbs {
    pub fn new_actor<S: Signature>(id_csr: IdCsr<S>) -> Result<Self, ConstraintError> {
        todo!()
    }
}

impl<P: Profile> TryFrom<TbsCertificateInner<P>> for IdCertTbs {
    type Error = TbsCertToIdCert;

    fn try_from(value: TbsCertificateInner<P>) -> Result<Self, Self::Error> {
        value.subject.validate()?;

        let capabilities = match value.extensions {
            Some(ext) => Capabilities::try_from(ext)?,
            None => return Err(TbsCertToIdCert::Extensions),
        };

        let subject_public_key_info = PublicKeyInfo::from(value.subject_public_key_info);

        let serial_number = match Uint::new(value.serial_number.as_bytes()) {
            Ok(snum) => snum,
            Err(e) => return Err(TbsCertToIdCert::Signature(e)),
        };

        Ok(IdCertTbs {
            serial_number,
            signature_algorithm: value.signature,
            issuer: value.issuer,
            validity: value.validity,
            subject: value.subject,
            subject_public_key_info,
            capabilities,
        })
    }
}

impl<P: Profile> TryFrom<IdCertTbs> for TbsCertificateInner<P> {
    type Error = IdCertToTbsCert;

    fn try_from(value: IdCertTbs) -> Result<Self, Self::Error> {
        let serial_number = match SerialNumber::<P>::new(value.serial_number.as_bytes()) {
            Ok(sernum) => sernum,
            Err(e) => return Err(IdCertToTbsCert::SerialNumber(e)),
        };

        let signature = AlgorithmIdentifierOwned {
            oid: value.signature_algorithm.oid,
            parameters: value.signature_algorithm.parameters,
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
            subject_unique_id: None,
            extensions: Some(Extensions::from(value.capabilities)),
        })
    }
}
