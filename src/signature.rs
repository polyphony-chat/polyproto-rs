// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::Any;
use spki::{AlgorithmIdentifier, ObjectIdentifier};

/// Represents a signature algorithm usable in X.509-like environments.
pub trait SignatureAlgorithm: From<AlgorithmIdentifier<Any>> + PartialEq + Eq + Clone {
    /// Object ID notation of this signature algorithm
    fn oid(&self) -> ObjectIdentifier;
    /// Parameters for this signature algorithm. The contents of this parameters' field will vary
    /// according to the algorithm identified.
    fn parameters(&self) -> Option<Any>;
    /// The signature algorithms' common name
    fn name(&self) -> &str;
}

/// A signature value, generated using a [SignatureAlgorithm]
pub trait Signature: PartialEq + Eq {
    type SignatureAlgorithm: SignatureAlgorithm;
    type Signature;
    /// The signature value
    fn signature(&self) -> &Self::Signature;
    /// The [SignatureAlgorithm] used to create this signature.
    fn algorithm(&self) -> &Self::SignatureAlgorithm;
}
