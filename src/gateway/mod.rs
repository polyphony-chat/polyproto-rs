// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Debug;
use std::sync::Arc;

use crate::api::Session;
use crate::key::PrivateKey;
use crate::signature::Signature;

mod backends;
use backends::heartbeat::Heartbeat;
pub use backends::BackendBehavior;
use backends::{Closed, GatewayMessage};
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub(crate) static KILL_LOG_MESSAGE: &str = "Received kill signal, shutting down";

#[derive(Debug)]
/// A generic gateway, making no assumptions about the gateway backend in use. Communication is
/// abstracted through the use of [tokio::sync::watch] channels, making sending and consumption of
/// messages to/from a gateway server trivial.
///
/// [Gateway] handles most of the gateway connection lifecycle. This includes building a connection,
/// parsing [Hello] information and exhibiting proper [Heartbeat] behavior, including responding to
/// [RequestHeartbeat] messages.
pub struct Gateway<S: Signature, T: PrivateKey<S>>
where
    S: Debug,
    <T as crate::key::PrivateKey<S>>::PublicKey: Debug,
{
    /// A reference to a corresponding [Session].
    pub session: Arc<Session<S, T>>,
    /// This channel can be used to send [GatewayMessages](GatewayMessage) to the gateway server.
    pub send_channel: watch::Sender<GatewayMessage>,
    /// This channel can be used to receive [GatewayMessages](GatewayMessage) from the gateway server.
    pub receive_channel: watch::Receiver<GatewayMessage>,
    kill_send: watch::Sender<Closed>,
    /// Tokio task running "receiver" logic
    receiver_task: JoinHandle<()>,
    /// Tokio task running "sender" logic
    sender_task: JoinHandle<()>,
    /// Tokio task running heartbeat logic
    heartbeat_task: Heartbeat,
}
