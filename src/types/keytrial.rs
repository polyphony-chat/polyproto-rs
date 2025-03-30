// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::certs::idcert::IdCert;
use crate::errors::PublicKeyError;
use crate::key::{PrivateKey, PublicKey};
use crate::signature::Signature;

use super::der::asn1::Uint;

#[cfg_attr(feature = "serde", serde_with::serde_as)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A completed key trial, as an actor would send to the server.
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct KeyTrialResponse {
    /// The signature produced by signing the key trial string using a private identity key.
    pub signature: String,
    #[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
    /// The serial number of the ID-Cert corresponding to the private identity key used to sign the key trial string.
    pub serial_number: u64,
}

#[cfg_attr(feature = "serde", serde_with::serde_as)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A key trial as sent from the server to an actor.
/// Used to verify an actor's private identity key possession, without revealing the private key itself
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct KeyTrial {
    /// The key trial, which the client should sign with their private identity key.
    pub trial: String,
    #[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
    /// The UNIX timestamp after which the key trial expires.
    pub expires: u64,
}

impl KeyTrialResponse {
    /// Try to convert `self.signature` to a signature `S where S: polyproto::signature::Signature`
    pub fn signature_as_signature<S: Signature>(&self) -> Result<S, PublicKeyError> {
        S::try_from_hex(&self.signature).map_err(|_| PublicKeyError::BadSignature)
    }

    /// Verify that a [KeyTrialResponse] is valid for a given actor public key and a given [KeyTrial].
    ///
    /// ## Parameters
    ///
    /// - `verifying_timestamp_unix`: The timestamp at which the [KeyTrialResponse] was received to ensure,
    ///   that the response was generated in the timeframe dictated by `(KeyTrial as self).expires`.
    pub fn verify_response<S: Signature, P: PublicKey<S>>(
        &self,
        key_trial: &KeyTrial,
        verifying_timestamp_unix: u64,
        actor_public_key: &P,
    ) -> Result<(), PublicKeyError> {
        let signature = self.signature_as_signature::<S>()?;
        if key_trial.expires > verifying_timestamp_unix {
            Err(PublicKeyError::BadSignature)
        } else {
            actor_public_key.verify_signature(&signature, key_trial.trial.as_bytes())
        }
    }
}

impl KeyTrial {
    /// With a provided certificate and the matching `signing_key`, generate a [KeyTrialResponse] from
    /// a [KeyTrial].
    ///
    /// Does not check if the provided `signing_key` corresponds to the public key in the [IdCert].
    pub fn into_response<T: PrivateKey<S>, S: Signature>(
        self,
        signing_key: T,
        cert: &IdCert<S, T::PublicKey>,
    ) -> Result<KeyTrialResponse, PublicKeyError>
    where
        T::PublicKey: PublicKey<S>,
    {
        let signature = signing_key.sign(self.trial.as_bytes());
        Ok(KeyTrialResponse {
            signature: signature.as_hex(),
            serial_number: u64::try_from(Uint(cert.id_cert_tbs.serial_number.clone()))
                .map_err(|_| PublicKeyError::BadPublicKeyInfo)?,
        })
    }
}
