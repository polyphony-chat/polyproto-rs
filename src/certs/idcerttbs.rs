// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::Uint;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::certificate::{Profile, TbsCertificateInner};
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::TbsCertificate;

use crate::errors::CertificateConversionError;
use crate::key::PublicKey;
use crate::signature::Signature;
use crate::Constrained;

use super::capabilities::Capabilities;
use super::idcsr::IdCsr;
use super::{PublicKeyInfo, Target};

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
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IdCertTbs<S: Signature, P: PublicKey<S>> {
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
    /// The subjects' public key: [PublicKey].
    pub subject_public_key: P,
    /// Capabilities assigned to the subject of the certificate.
    pub capabilities: Capabilities,
    /// PhantomData
    pub(crate) s: std::marker::PhantomData<S>,
}

impl<S: Signature, P: PublicKey<S>> IdCertTbs<S, P> {
    /// Create a new [IdCertTbs] by passing an [IdCsr] and other supplementary information. Returns
    /// an error, if the provided IdCsr or issuer [Name] do not pass [Constrained] verification,
    /// i.e. if they are not up to polyproto specification. Also fails if the provided IdCsr has
    /// the [BasicConstraints] "ca" flag set to `true`.
    ///
    /// See [IdCertTbs::from_ca_csr()] when trying to create a new CA certificate for home servers.
    ///
    /// The resulting `IdCertTbs` is guaranteed to be well-formed and up to polyproto specification,
    /// for the usage context of an actor certificate.
    pub fn from_actor_csr(
        id_csr: IdCsr<S, P>,
        serial_number: Uint,
        signature_algorithm: AlgorithmIdentifierOwned,
        issuer: Name,
        validity: Validity,
    ) -> Result<Self, CertificateConversionError> {
        id_csr.validate(Some(Target::Actor))?;
        let cert_tbs = IdCertTbs {
            serial_number,
            signature_algorithm,
            issuer,
            validity,
            subject: id_csr.inner_csr.subject,
            subject_public_key: id_csr.inner_csr.subject_public_key,
            capabilities: id_csr.inner_csr.capabilities,
            s: std::marker::PhantomData,
        };
        cert_tbs.validate(Some(Target::Actor))?;
        Ok(cert_tbs)
    }

    /// Create a new [IdCertTbs] by passing an [IdCsr] and other supplementary information. Returns
    /// an error, if the provided IdCsr or issuer [Name] do not pass [Constrained] verification,
    /// i.e. if they are not up to polyproto specification. Also fails if the provided IdCsr has
    /// the [BasicConstraints] "ca" flag set to `false`.
    ///
    /// See [IdCertTbs::from_actor_csr()] when trying to create a new actor certificate.
    ///
    /// The resulting `IdCertTbs` is guaranteed to be well-formed and up to polyproto specification,
    /// for the usage context of a home server certificate.
    pub fn from_ca_csr(
        id_csr: IdCsr<S, P>,
        serial_number: Uint,
        signature_algorithm: AlgorithmIdentifierOwned,
        issuer: Name,
        validity: Validity,
    ) -> Result<Self, CertificateConversionError> {
        id_csr.validate(Some(Target::HomeServer))?;
        let cert_tbs = IdCertTbs {
            serial_number,
            signature_algorithm,
            issuer,
            validity,
            subject: id_csr.inner_csr.subject,
            subject_public_key: id_csr.inner_csr.subject_public_key,
            capabilities: id_csr.inner_csr.capabilities,
            s: std::marker::PhantomData,
        };
        cert_tbs.validate(Some(Target::HomeServer))?;
        Ok(cert_tbs)
    }

    /// Encode this type as DER, returning a byte vector.
    pub fn to_der(self) -> Result<Vec<u8>, CertificateConversionError> {
        Ok(TbsCertificate::try_from(self)?.to_der()?)
    }

    /// Create an [IdCertTbs] from a byte slice containing a DER encoded PKCS #10 CSR. The resulting
    /// `IdCertTbs` is guaranteed to be well-formed and up to polyproto specification,
    /// if the correct [Target] for the certificates' intended usage context is provided.
    pub fn from_der(
        bytes: &[u8],
        target: Option<Target>,
    ) -> Result<Self, CertificateConversionError> {
        let cert = IdCertTbs::from_der_unchecked(bytes)?;
        cert.validate(target)?;
        Ok(cert)
    }

    /// Create an unchecked [IdCertTbs] from a byte slice containing a DER encoded PKCS #10 CSR. The caller is
    /// responsible for verifying the correctness of this `IdCertTbs` using
    /// the [Constrained] trait before using it.
    pub fn from_der_unchecked(bytes: &[u8]) -> Result<Self, CertificateConversionError> {
        let cert = IdCertTbs::try_from(TbsCertificate::from_der(bytes)?)?;
        Ok(cert)
    }

    /// Checks if the IdCertTbs was valid at a given UNIX time. Does not validate the certificate
    /// against the polyproto specification.
    pub(crate) fn valid_at(&self, time: u64) -> bool {
        time >= self.validity.not_before.to_unix_duration().as_secs()
            && time <= self.validity.not_after.to_unix_duration().as_secs()
    }
}

impl<P: Profile, S: Signature, Q: PublicKey<S>> TryFrom<TbsCertificateInner<P>>
    for IdCertTbs<S, Q>
{
    type Error = CertificateConversionError;

    /// Tries to convert a [TbsCertificateInner] into an [IdCertTbs]. The Ok() variant of this Result
    /// is an unverified `IdCertTbs`. If this conversion is called manually, the caller is responsible
    /// for verifying the `IdCertTbs` using the [Constrained] trait.
    fn try_from(value: TbsCertificateInner<P>) -> Result<Self, Self::Error> {
        value.subject.validate(None)?;

        let capabilities =
            match value.extensions {
                Some(ext) => Capabilities::try_from(ext)?,
                None => return Err(CertificateConversionError::InvalidInput(
                    crate::errors::base::InvalidInput::Malformed(
                        "field 'extensions' was None. Expected: Some(x509_cert::ext::Extensions)"
                            .to_string(),
                    ),
                )),
            };
        let subject_public_key_info = PublicKey::try_from_public_key_info(PublicKeyInfo::from(
            value.subject_public_key_info,
        ))?;

        let serial_number = Uint::new(value.serial_number.as_bytes())?;

        Ok(Self {
            serial_number,
            signature_algorithm: value.signature,
            issuer: value.issuer,
            validity: value.validity,
            subject: value.subject,
            subject_public_key: subject_public_key_info,
            capabilities,
            s: std::marker::PhantomData,
        })
    }
}

impl<P: Profile, S: Signature, Q: PublicKey<S>> TryFrom<IdCertTbs<S, Q>>
    for TbsCertificateInner<P>
{
    type Error = CertificateConversionError;

    fn try_from(value: IdCertTbs<S, Q>) -> Result<Self, Self::Error> {
        let serial_number = match SerialNumber::<P>::new(value.serial_number.as_bytes()) {
            Ok(sernum) => sernum,
            Err(e) => {
                return Err(CertificateConversionError::InvalidInput(
                    crate::errors::base::InvalidInput::Malformed(format!(
                        "Could not convert serial number: {}",
                        e
                    )),
                ))
            }
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
            subject_public_key_info: value.subject_public_key.public_key_info().into(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(Extensions::try_from(value.capabilities)?),
        })
    }
}
