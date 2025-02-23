use std::fmt::Debug;
use std::sync::Arc;

use crate::api::Session;
use crate::key::PrivateKey;
use crate::signature::Signature;

mod backends;
pub use backends::{BackendBehavior, GatewayBackend};

#[derive(Clone, Debug)]
pub struct Gateway<S: Signature, T: PrivateKey<S>>
where
    S: Debug,
    <T as crate::key::PrivateKey<S>>::PublicKey: Debug,
{
    /// A reference to a corresponding [Session].
    pub session: Arc<Session<S, T>>,
}
