// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use spki::AlgorithmIdentifierOwned;

use crate::certs::PublicKeyInfo;
use crate::errors::{CertificateConversionError, PublicKeyError};
use crate::signature::Signature;

/// A cryptographic private key generated by a [AlgorithmIdentifierOwned], with
/// a corresponding [PublicKey]
pub trait PrivateKey<S: Signature>: PartialEq + Eq {
    /// The public key type corresponding to this private key.
    type PublicKey: PublicKey<S>;
    /// Returns the public key corresponding to this private key.
    fn pubkey(&self) -> &Self::PublicKey;
    /// Creates a [Signature] for the given data.
    fn sign(&self, data: &[u8]) -> S;
    /// Returns the [AlgorithmIdentifierOwned] associated with this key's signature algorithm.
    fn algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
        S::algorithm_identifier()
    }
}

/// A cryptographic public key generated by a [SignatureAlgorithm].
pub trait PublicKey<S: Signature>: PartialEq + Eq + Clone {
    /// Verifies the correctness of a given [Signature] for a given piece of data.
    ///
    /// Implementations of this associated method should mitigate weak key forgery.
    fn verify_signature(&self, signature: &S, data: &[u8]) -> Result<(), PublicKeyError>;
    /// Returns the [PublicKeyInfo] associated with this key's signature algorithm.
    fn public_key_info(&self) -> PublicKeyInfo;
    /// Returns the [AlgorithmIdentifierOwned] associated with this key's signature algorithm.
    fn algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
        S::algorithm_identifier()
    }
    /// Creates a new [Self] from a [PublicKeyInfo].
    fn try_from_public_key_info(public_key_info: PublicKeyInfo) -> Result<Self, CertificateConversionError>;
}
