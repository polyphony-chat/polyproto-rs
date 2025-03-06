// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Debug;
use std::sync::Arc;

use crate::api::Session;
use crate::key::PrivateKey;
use crate::signature::Signature;

/// Gateway backend code.
pub mod backends;
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
    _kill_send: watch::Sender<Closed>,
    /// Tokio task running "receiver" logic
    _receiver_task: JoinHandle<()>,
    /// Tokio task running "sender" logic
    _sender_task: JoinHandle<()>,
    /// Tokio task running heartbeat logic
    _heartbeat_task: Heartbeat,
}

/// Send a kill signal through a dedicated `watch` sender.
///
/// ## Example
///
/// ```
/// # use polyproto::gateway::backends::Closed;
/// # use polyproto::gateway::kill;
/// let sender = tokio::sync::watch::channel(Closed::Exhausted).0;
/// // info is a `log::` loglevel macro, the last argument is the log message.
/// kill!(sender, info, "We had to do it to 'em.");
/// ```
#[macro_export]
macro_rules! kill {
    ($kill_send:ident, $log_level:ident, $msg:expr) => {{
        log::$log_level!("{}", $msg);
        match $kill_send.send(Closed::Error($msg.to_string())) {
            Ok(_) => log::trace!("Sent kill signal successfully"),
            Err(kill_error) => log::trace!(
                "Sent kill signal, received error. Shutting down regardless: {kill_error}"
            ),
        };
    }};
}

pub use kill;

#[cfg(test)]
mod test {
    use tokio::sync::watch;

    use crate::testing_utils::init_logger;

    use super::backends::Closed;

    #[test]
    fn kill_test() {
        init_logger();
        let (send, receive) = watch::channel(Closed::Exhausted);
        kill!(send, info, "this is a test!");
        assert!(receive.has_changed().unwrap())
    }

    #[test]
    fn kill_test_cant_send() {
        init_logger();
        let (send, receive) = watch::channel(Closed::Exhausted);
        drop(receive);
        kill!(send, info, "this is a test!");
    }
}
