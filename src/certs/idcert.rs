// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::Uint;
use der::pem::LineEnding;
use der::{Decode, DecodePem, Encode, EncodePem};
use x509_cert::name::Name;
use x509_cert::time::Validity;
use x509_cert::Certificate;

use crate::api::HttpClient;
use crate::errors::{ConstraintError, ConversionError, InvalidCert, ERR_CERTIFICATE_TO_DER_ERROR};
use crate::key::{PrivateKey, PublicKey};
use crate::signature::Signature;
use crate::Constrained;

use super::idcerttbs::IdCertTbs;
use super::idcsr::IdCsr;
use super::Target;

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
/// - **P**: A [PublicKey] type `P` which can be used to verify [Signature]s of type `S`.
///
/// ## Verifying an ID-Cert
///
/// To verify an ID-Cert, use the [full_verify_actor()] or [full_verify_home_server()] methods.
/// These methods will check if the certificate is valid at a given time, if the signature is correct,
/// and if the certificate is well-formed and up to polyproto specification. Using the [Constrained]
/// trait and its associated `verify()` method is **not** sufficient for this purpose.
///
/// If you only need to check if the certificate is valid at a given time, use the [valid_at()] method.
///
/// If you only need to verify whether the certificate is well-formed, use the [Constrained] trait
/// and its associated `verify()` method.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IdCert<S: Signature, P: PublicKey<S>> {
    /// Inner TBS (To be signed) certificate
    pub id_cert_tbs: IdCertTbs<S, P>,
    /// Signature for the TBS certificate
    pub signature: S,
}

impl<S: Signature, P: PublicKey<S>> IdCert<S, P> {
    /// Create a new [IdCert] by passing an [IdCsr] and other supplementary information. Returns
    /// an error, if the provided IdCsr or issuer [Name] do not pass [Constrained] verification,
    /// i.e. if they are not up to polyproto specification.
    ///
    /// See [IdCert::from_actor_csr()] when trying to create a new actor certificate.
    ///
    /// ## Safety guarantees
    ///
    /// The resulting `IdCert` is guaranteed to be well-formed and up to polyproto specification,
    /// for the usage context of a home server certificate. Assuming that cryptography has been
    /// implemented correctly, the certificate is also guaranteed to have a valid signature. For a
    /// more detailed list of guarantees, see [IdCert::full_home_server()].
    ///
    /// ## Parameters
    ///
    /// - `id_csr`: The [IdCsr] to create the new certificate from.
    /// - `signing_key`: The home server's private key, used to sign the new certificate.
    /// - `serial_number`: The serial number that should be assigned to the new certificate.
    /// - `issuer`: The [Name] of the issuer of the resulting certificate.
    /// - `validity`: The [Validity] period of the resulting certificate.
    pub fn from_ca_csr(
        id_csr: IdCsr<S, P>,
        signing_key: &impl PrivateKey<S, PublicKey = P>,
        serial_number: Uint,
        issuer: Name,
        validity: Validity,
    ) -> Result<Self, ConversionError> {
        let signature_algorithm = signing_key.algorithm_identifier();
        let id_cert_tbs = IdCertTbs::<S, P> {
            serial_number,
            signature_algorithm,
            issuer,
            validity,
            subject: id_csr.inner_csr.subject,
            subject_public_key: id_csr.inner_csr.subject_public_key,
            capabilities: id_csr.inner_csr.capabilities,
            s: std::marker::PhantomData,
        };
        let signature = signing_key.sign(&id_cert_tbs.clone().to_der()?);
        let cert = IdCert {
            id_cert_tbs,
            signature,
        };
        cert.validate(Some(Target::HomeServer))?;
        Ok(cert)
    }

    /// Create a new [IdCert] by passing an [IdCsr] and other supplementary information. Returns
    /// an error, if the provided IdCsr or issuer [Name] do not pass [Constrained] verification,
    /// i.e. if they are not up to polyproto specification.
    ///
    /// See [IdCert::from_ca_csr()] when trying to create a new ca certificate.
    ///
    /// ## Safety guarantees
    ///
    /// The resulting `IdCert` is guaranteed to be well-formed and up to polyproto specification,
    /// for the usage context of an actor certificate. Assuming that cryptography has been
    /// implemented correctly, the certificate is also guaranteed to have a valid signature. For a
    /// more detailed list of guarantees, see [IdCert::full_verify_actor()].
    ///
    /// ## Parameters
    ///
    /// - `id_csr`: The [IdCsr] to create the new certificate from.
    /// - `signing_key`: The home server's private key, used to sign the new certificate.
    /// - `serial_number`: The serial number that should be assigned to the new certificate.
    /// - `issuer`: The [Name] of the issuer of the resulting certificate.
    /// - `validity`: The [Validity] period of the resulting certificate.
    pub fn from_actor_csr(
        id_csr: IdCsr<S, P>,
        signing_key: &impl PrivateKey<S, PublicKey = P>,
        serial_number: Uint,
        issuer: Name,
        validity: Validity,
    ) -> Result<Self, ConversionError> {
        log::trace!("[IdCert::from_actor_csr()] creating actor certificate");
        let signature_algorithm = signing_key.algorithm_identifier();
        log::trace!("[IdCert::from_actor_csr()] creating IdCertTbs");
        log::trace!("[IdCert::from_actor_csr()] Issuer: {}", issuer.to_string());
        log::trace!(
            "[IdCert::from_actor_csr()] Subject: {}",
            id_csr.inner_csr.subject.to_string()
        );
        let id_cert_tbs = IdCertTbs::<S, P> {
            serial_number,
            signature_algorithm,
            issuer,
            validity,
            subject: id_csr.inner_csr.subject,
            subject_public_key: id_csr.inner_csr.subject_public_key,
            capabilities: id_csr.inner_csr.capabilities,
            s: std::marker::PhantomData,
        };
        log::trace!("[IdCert::from_actor_csr()] creating Signature");
        let signature = signing_key.sign(&id_cert_tbs.clone().to_der()?);
        let cert = IdCert {
            id_cert_tbs,
            signature,
        };
        log::trace!(
            "[IdCert::from_actor_csr()] validating certificate with target {:?}",
            Some(Target::Actor)
        );
        cert.validate(Some(Target::Actor))?;
        Ok(cert)
    }

    /// Create an [IdCert] from a byte slice containing a DER encoded X.509 Certificate.
    /// The resulting `IdCert` has the same validity guarantees as when using [IdCert::full_verify_actor()]
    /// or [IdCert::full_verify_home_server()].
    pub fn from_der(
        value: &[u8],
        target: Target,
        time: u64,
        home_server_public_key: &P,
    ) -> Result<Self, InvalidCert> {
        let cert = match IdCert::from_der_unchecked(value) {
            Ok(cert) => cert,
            Err(e) => {
                return Err(InvalidCert::InvalidProperties(ConstraintError::Malformed(
                    Some(e.to_string()),
                )))
            }
        };
        match target {
            Target::Actor => {
                cert.full_verify_actor(time, home_server_public_key)?;
            }
            Target::HomeServer => {
                cert.full_verify_home_server(time)?;
            }
        }
        Ok(cert)
    }

    /// Create an unchecked [IdCert] from a byte slice containing a DER encoded X.509 Certificate.
    /// The caller is responsible for verifying the correctness of this `IdCert` using
    /// the [Constrained] trait before using it.
    pub fn from_der_unchecked(value: &[u8]) -> Result<Self, ConversionError> {
        let cert = IdCert::try_from(Certificate::from_der(value)?)?;
        Ok(cert)
    }

    /// Encode this type as DER, returning a byte vector.
    pub fn to_der(self) -> Result<Vec<u8>, ConversionError> {
        Ok(Certificate::try_from(self)?.to_der()?)
    }

    /// Create an [IdCert] from a byte slice containing a PEM encoded X.509 Certificate.
    /// The resulting `IdCert` has the same validity guarantees as when using [IdCert::full_verify_actor()]
    /// or [IdCert::full_verify_home_server()].
    pub fn from_pem(
        pem: &str,
        target: Target,
        time: u64,
        home_server_public_key: &P,
    ) -> Result<Self, InvalidCert> {
        let cert = match IdCert::from_pem_unchecked(pem) {
            Ok(cert) => cert,
            Err(e) => {
                return Err(InvalidCert::InvalidProperties(ConstraintError::Malformed(
                    Some(e.to_string()),
                )))
            }
        };
        match target {
            Target::Actor => {
                cert.full_verify_actor(time, home_server_public_key)?;
            }
            Target::HomeServer => {
                cert.full_verify_home_server(time)?;
            }
        }
        Ok(cert)
    }

    /// Create an unchecked [IdCert] from a byte slice containing a PEM encoded X.509 Certificate.
    /// The caller is responsible for verifying the correctness of this `IdCert` using
    /// either [IdCert::full_verify_actor()] or [IdCert::full_verify_home_server()] before using it.
    pub fn from_pem_unchecked(pem: &str) -> Result<Self, ConversionError> {
        let cert = IdCert::try_from(Certificate::from_pem(pem)?)?;
        Ok(cert)
    }

    /// Encode this type as PEM, returning a string.
    pub fn to_pem(self, line_ending: LineEnding) -> Result<String, ConversionError> {
        Ok(Certificate::try_from(self)?.to_pem(line_ending)?)
    }

    /// Returns a byte vector containing the DER encoded IdCertTbs. This data is encoded
    /// in the signature field of the certificate, and can be used to verify the signature.
    ///
    /// This is a shorthand for `self.id_cert_tbs.clone().to_der()`, since intuitively, one might
    /// try to verify the signature of the certificate by using `self.to_der()`, which will result
    /// in an error.
    pub fn signature_data(&self) -> Result<Vec<u8>, ConversionError> {
        self.id_cert_tbs.clone().to_der()
    }

    /// Checks, if the certificate is valid at a given time. Does not check if the certificate is
    /// well-formed, up to polyproto specification or if the signature is correct. If you need to
    /// verify these properties, use either `full_verify_actor` or `full_verify_home_server`
    /// instead.
    pub fn valid_at(&self, time: u64) -> bool {
        self.id_cert_tbs.valid_at(time)
    }

    /// Performs verification of the certificate, checking for the following properties:
    ///
    /// - The certificate is valid at the given `time`
    /// - The signature of the certificate is correct
    /// - The certificate is well-formed and up to polyproto specification
    /// - All parts that make up the certificate are well-formed and up to polyproto specification
    ///
    /// ## Difference between this and `Constrained::validate()`
    ///
    /// While [Constrained] and the associated `validate` method implementation for this type check
    /// for well-formedness in context of the polyproto specification, the `full_verify_actor` and
    /// `full_verify_homeserver` provide cryptographic verification in *addition* by checking if
    /// the certificates' signature matches the data and if the signature was indeed generated by
    /// the home server. This, of course, makes the assumption that the public key can be trusted.
    pub fn full_verify_actor(
        &self,
        time: u64,
        home_server_public_key: &P,
    ) -> Result<(), InvalidCert> {
        if !self.valid_at(time) {
            return Err(InvalidCert::InvalidValidity);
        }
        self.validate(Some(Target::Actor))?;
        log::trace!("[IdCert::full_verify_actor(&self)] verifying signature (actor certificate)");
        let der = match self.id_cert_tbs.clone().to_der() {
            Ok(der) => der,
            Err(_) => {
                log::warn!(
                    "[IdCert::full_verify_actor(&self)] {}",
                    ERR_CERTIFICATE_TO_DER_ERROR
                );
                return Err(InvalidCert::InvalidProperties(ConstraintError::Malformed(
                    Some(ERR_CERTIFICATE_TO_DER_ERROR.to_string()),
                )));
            }
        };
        Ok(home_server_public_key.verify_signature(&self.signature, &der)?)
    }

    /// Performs verification of the certificate, checking for the following properties:
    ///
    /// - The certificate is valid at the given `time`
    /// - The signature of the certificate is correct
    /// - The certificate is well-formed and up to polyproto specification
    /// - All parts that make up the certificate are well-formed and up to polyproto specification
    ///
    /// ## Difference between this and `Constrained::validate()`
    ///
    /// While [Constrained] and the associated `validate` method implementation for this type check
    /// for well-formedness in context of the polyproto specification, the `full_verify_actor` and
    /// `full_verify_homeserver` provide cryptographic verification in *addition* by checking if
    /// the certificates' signature matches the data and if the signature was indeed generated by
    /// the home server. This, of course, makes the assumption that the public key can be trusted.
    pub fn full_verify_home_server(&self, time: u64) -> Result<(), InvalidCert> {
        self.validate(Some(Target::HomeServer))?;
        if !self.valid_at(time) {
            return Err(InvalidCert::InvalidValidity);
        }
        let der = match self.id_cert_tbs.clone().to_der() {
            Ok(data) => data,
            Err(_) => {
                log::warn!(
                    "[IdCert::full_verify_home_server(&self)] {}",
                    ERR_CERTIFICATE_TO_DER_ERROR
                );
                return Err(InvalidCert::InvalidProperties(ConstraintError::Malformed(
                    Some(ERR_CERTIFICATE_TO_DER_ERROR.to_string()),
                )));
            }
        };
        log::trace!(
            "[IdCert::full_verify_home_server(&self)] verifying signature (self-signed IdCert)"
        );
        Ok(self
            .id_cert_tbs
            .subject_public_key
            .verify_signature(&self.signature, &der)?)
    }

    /// From an [IdCertTbs], retrieve the `issuer` as a [Url].
    pub fn issuer_url(&self) -> Result<url::Url, url::ParseError> {
        self.id_cert_tbs.issuer_url()
    }

    /// _Sorry for the long name._
    ///
    /// Verifies the conditions listed in [section #3.1](https://docs.polyphony.chat/Protocol%20Specifications/core/#31-well-known)
    /// of the polyproto protocol specification regarding hosting a polyproto server under a different
    /// domain name than the one visible to the public.
    ///
    /// ## Returns
    ///
    /// ### `false`, if
    ///
    /// - Any of the 5 conditions listed in section #3.1 are found to be violated
    /// - The server hosting the "visible domain name" is not reachable, but the "actual domain name"
    ///   server is reachable.
    /// - Both servers are not reachable
    ///
    /// ### `true`, if
    ///
    /// - The _magic_ 5 conditions are all met
    /// - There is no difference between the "visible" and "actual" domain names
    // TODO: Test me
    pub async fn verify_link_visible_actual_domain_names(&self, client: &HttpClient) -> bool {
        self.id_cert_tbs
            .verify_link_visible_actual_domain_names(client)
            .await
    }
}

impl<S: Signature, P: PublicKey<S>> TryFrom<IdCert<S, P>> for Certificate {
    type Error = ConversionError;
    fn try_from(value: IdCert<S, P>) -> Result<Self, Self::Error> {
        Ok(Self {
            tbs_certificate: value.id_cert_tbs.clone().try_into()?,
            signature_algorithm: value.id_cert_tbs.signature_algorithm,
            signature: value.signature.to_bitstring()?,
        })
    }
}

impl<S: Signature, P: PublicKey<S>> TryFrom<Certificate> for IdCert<S, P> {
    type Error = ConversionError;
    /// Tries to convert a [Certificate] into an [IdCert]. The Ok() variant of this method
    /// contains the `IdCert` if the conversion was successful. If this conversion is called
    /// manually, the caller is responsible for verifying the correctness of this `IdCert` using
    /// the [Constrained] trait.
    fn try_from(value: Certificate) -> Result<Self, Self::Error> {
        let id_cert_tbs = value.tbs_certificate.try_into()?;
        let signature = S::from_bytes(value.signature.raw_bytes());
        let cert = IdCert {
            id_cert_tbs,
            signature,
        };
        Ok(cert)
    }
}
