// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::Uint;
use spki::AlgorithmIdentifierOwned;
use x509_cert::name::Name;
use x509_cert::time::Validity;

use crate::errors::composite::IdCertError;
use crate::key::{PrivateKey, PublicKey};
use crate::signature::Signature;

use super::idcerttbs::IdCertTbs;
use super::idcsr::IdCsr;

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
/// - **P**: A [PublicKey] type P which can be used to verify [Signature]s of type S.
#[derive(Debug, PartialEq, Eq)]
pub struct IdCert<S: Signature, P: PublicKey<S>> {
    /// Inner TBS (To be signed) certificate
    pub id_cert_tbs: IdCertTbs<S, P>,
    /// Signature for the TBS certificate
    pub signature: S,
}

impl<S: Signature, P: PublicKey<S>> IdCert<S, P> {
    pub fn from_ca_csr(
        id_csr: IdCsr<S, P>,
        signing_key: &impl PrivateKey<S, PublicKey = P>,
        serial_number: Uint,
        signature_algorithm: AlgorithmIdentifierOwned,
        issuer: Name,
        validity: Validity,
    ) -> Result<Self, IdCertError> {
        let id_cert_tbs =
            IdCertTbs::from_ca_csr(id_csr, serial_number, signature_algorithm, issuer, validity)?;
        let signature = signing_key.sign(&id_cert_tbs.clone().to_der()?);
        Ok(IdCert {
            id_cert_tbs,
            signature,
        })
    }

    pub fn from_actor_csr(
        id_csr: IdCsr<S, P>,
        signing_key: &impl PrivateKey<S, PublicKey = P>,
        serial_number: Uint,
        signature_algorithm: AlgorithmIdentifierOwned,
        issuer: Name,
        validity: Validity,
    ) -> Result<Self, IdCertError> {
        let id_cert_tbs = IdCertTbs::from_actor_csr(
            id_csr,
            serial_number,
            signature_algorithm,
            issuer,
            validity,
        )?;
        let signature = signing_key.sign(&id_cert_tbs.clone().to_der()?);
        Ok(IdCert {
            id_cert_tbs,
            signature,
        })
    }
}
