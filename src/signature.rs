// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::Any;
use spki::{AlgorithmIdentifier, ObjectIdentifier, SignatureBitStringEncoding};

/// Represents a signature algorithm usable in X.509-like environments.
pub trait SignatureAlgorithm:
    From<AlgorithmIdentifier<Any>> + Into<AlgorithmIdentifier<Any>> + PartialEq + Eq + Clone
{
    /// Object ID notation of this signature algorithm
    fn as_oid(&self) -> ObjectIdentifier;
    /// Parameters for this signature algorithm. The contents of this parameters' field will vary
    /// according to the algorithm identified.
    fn as_parameters(&self) -> Option<Any>;
    /// The signature algorithms' common name
    fn name(&self) -> &str;
}

/// A signature value, generated using a [SignatureAlgorithm]
pub trait Signature: PartialEq + Eq + SignatureBitStringEncoding {
    type SignatureAlgorithm: SignatureAlgorithm;
    type Signature;
    /// The signature value
    fn as_signature(&self) -> &Self::Signature;
    /// The [SignatureAlgorithm] used to create this signature.
    fn as_algorithm(&self) -> &Self::SignatureAlgorithm;
}
