// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use spki::SignatureBitStringEncoding;

use crate::certs::PublicKeyInfo;

/// A signature value, generated using a [SignatureAlgorithm]
pub trait Signature: PartialEq + Eq + SignatureBitStringEncoding {
    type Signature;
    /// The signature value
    fn as_signature(&self) -> &Self::Signature;
    /// The [PublicKeyInfo] associated with this signature
    fn public_key_info() -> PublicKeyInfo;
}
