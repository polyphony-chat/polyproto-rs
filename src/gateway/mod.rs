// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Debug;
use std::sync::Arc;

use crate::api::Session;
use crate::key::PrivateKey;
use crate::signature::Signature;

mod backends;
pub use backends::BackendBehavior;
use backends::{Closed, GatewayMessage};
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub(crate) static KILL_LOG_MESSAGE: &str = "Received kill signal, shutting down";

#[derive(Debug)]
pub struct Gateway<S: Signature, T: PrivateKey<S>>
where
    S: Debug,
    <T as crate::key::PrivateKey<S>>::PublicKey: Debug,
{
    /// A reference to a corresponding [Session].
    pub session: Arc<Session<S, T>>,
    pub send_channel: watch::Sender<GatewayMessage>,
    pub receive_channel: watch::Receiver<GatewayMessage>,
    kill_send: watch::Sender<Closed>,
    receiver_task: JoinHandle<()>,
    sender_task: JoinHandle<()>,
}
