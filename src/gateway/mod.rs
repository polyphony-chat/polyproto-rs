// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Debug;
use std::sync::Arc;

use crate::api::Session;
use crate::key::PrivateKey;
use crate::signature::Signature;

mod backends;
pub use backends::{BackendBehavior, GatewayBackend};

#[derive(Debug)]
pub struct Gateway<S: Signature, T: PrivateKey<S>>
where
    S: Debug,
    <T as crate::key::PrivateKey<S>>::PublicKey: Debug,
{
    /// A reference to a corresponding [Session].
    pub session: Arc<Session<S, T>>,
    backend: GatewayBackend,
}
