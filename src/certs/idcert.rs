// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.












use crate::signature::{Signature, SignatureAlgorithm};


use super::idcerttbs::IdCertTbs;

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
