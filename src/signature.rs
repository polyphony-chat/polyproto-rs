// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use spki::{AlgorithmIdentifierOwned, SignatureBitStringEncoding};

/// A signature value, generated using a [SignatureAlgorithm]
pub trait Signature: PartialEq + Eq + SignatureBitStringEncoding + Clone + ToString {
    /// The underlying signature type
    type Signature;
    /// The signature value
    fn as_signature(&self) -> &Self::Signature;
    /// The [AlgorithmIdentifierOwned] associated with this signature
    fn algorithm_identifier() -> AlgorithmIdentifierOwned;
    /// From a byte slice, create a new [Self]
    fn from_bytes(signature: &[u8]) -> Self;
    /// Encode [Self] as a byte vector.
    fn as_bytes(&self) -> Vec<u8>;
    /// Encode [Self] as bytes, represented as a [hex](https://en.wikipedia.org/wiki/Hexadecimal)-encoded [String].
    fn as_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
    /// Try to decode [Self] from a [hex](https://en.wikipedia.org/wiki/Hexadecimal)-encoded String.
    ///
    /// ## Errors
    ///
    /// Will error if the input string is not valid hex-encoded data.
    fn try_from_hex(hex_encoded_bytes: &str) -> Result<Self, crate::errors::InvalidInput> {
        Ok(Self::from_bytes(
            hex::decode(hex_encoded_bytes)
                .map_err(|e| crate::errors::InvalidInput::Malformed(e.to_string()))?
                .as_slice(),
        ))
    }
}
