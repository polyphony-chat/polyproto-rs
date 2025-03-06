// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub(crate) mod heartbeat;

use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;

use serde_json::from_str;
use tokio::sync::watch::error::SendError;
use url::Url;

use crate::api::Session;
use crate::errors::InvalidInput;
use crate::key::PrivateKey;
use crate::signature::Signature;
use crate::types::gateway::CoreEvent;

use super::Gateway;

#[cfg(not(feature = "wasm"))]
/// The tungstenite gateway backend. Used on non-wasm targets.
pub mod tungstenite;
#[cfg(feature = "wasm")]
/// The wasm gateway backend. Used only on the wasm-target.
pub mod wasm;

/// Trait defining required functionality for a gateway backend.
#[allow(async_fn_in_trait)] // We don't care about a `Send` bound here.
pub trait BackendBehavior: crate::sealer::Glue {
    /// Try and establish a WebSocket connection to a [Gateway] server under a certain [Url].
    /// The resulting [Gateway] will not yet have any messages sent to the server, meaning you will
    /// still have to authenticate and establish a Heartbeat loop.
    async fn connect<S, T>(
        &self,
        session: Arc<Session<S, T>>,
        gateway_url: &Url,
    ) -> GatewayResult<Gateway<S, T>>
    where
        S: Debug + Signature,
        <T as crate::key::PrivateKey<S>>::PublicKey: Debug,
        T: PrivateKey<S>;
    /// Get a [tokio::sync::broadcast::Receiver<GatewayMessage>], with which you can listen to incoming
    /// [GatewayMessages](GatewayMessage).
    ///
    /// ## Additional documentation
    ///
    /// Implementees of [BackendBehavior] use a [tokio::sync::broadcast::channel]
    /// to pass values to the [GatewayBackend]. As such, take a look at the documentation of [tokio::sync::broadcast::Receiver]
    /// to learn more about this function.
    fn subscribe(&self) -> tokio::sync::watch::Receiver<GatewayMessage>;
    /// Attempt to send a value to the [GatewayBackend] which will attempt to forward this message to the
    /// gateway server.
    ///
    /// ## Additional documentation
    ///
    /// Implementees of [BackendBehavior] use a [tokio::sync::broadcast::channel]
    /// to pass values to the [GatewayBackend]. As such, take a look at the documentation of [tokio::sync::broadcast::Sender]
    /// to learn more about this function.
    async fn send(&self, value: GatewayMessage) -> Result<(), SendError<GatewayMessage>>;
    /// Disconnect from the gateway with an optional [CloseMessage] to indicate a reason for the
    /// disconnect.
    async fn disconnect(
        &self,
        reason: Option<CloseMessage>,
    ) -> Result<(), SendError<GatewayMessage>>;
}

/// Alias for `Result<T, Error>`, where `Error` = [Error].
pub type GatewayResult<T> = Result<T, Error>;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
/// Gateway error type.
pub enum Error {
    #[error(transparent)]
    /// [ConnectionError]
    ConnectionError(#[from] ConnectionError),
    #[error("Backend has encountered the following error: {0}")]
    /// Backend specific error.
    BackendError(String),
    #[error("Expected hello as first message")]
    /// Server sent a message that wasn't a "Hello" event as its first message.
    NoHello,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
/// Connection errors.
pub enum ConnectionError {
    #[error("Unsupported connection scheme: {0}")]
    /// Thrown, if the connection scheme is unsupported.
    ConnectionScheme(String),
    #[error(transparent)]
    /// Returned when the gateway connection closes.
    Closed(Closed),
}

#[derive(thiserror::Error, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
/// Represents different reasons for why the gateway connection has closed.
pub enum Closed {
    /// The channel is exhausted, meaning the receiver can no longer receive messages.
    Exhausted,
    /// A different error has occurred.
    Error(String),
}

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Closed::Exhausted => f.write_str("Receiver stream exhausted"),
            Closed::Error(s) => f.write_str(s),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A gateway payload. Currently an abstraction of `ws_stream_wasm`'s and `tungstenite`'s error types,
/// to fully disconnect the public API from the backend in use.
pub enum GatewayMessage {
    /// Text!
    Text(String),
    /// Binary!
    Binary(Vec<u8>),
    /// Close!
    Close(Option<CloseMessage>),
}

impl TryFrom<GatewayMessage> for CoreEvent {
    type Error = InvalidInput;

    fn try_from(value: GatewayMessage) -> Result<Self, Self::Error> {
        let text = match value {
            GatewayMessage::Text(text) => text,
            GatewayMessage::Binary(_) => {
                return Err(InvalidInput::Malformed(
                    "Found binary message, expected string as HELLO payload".to_string(),
                ))
            }
            GatewayMessage::Close(_) => {
                return Err(InvalidInput::Malformed(
                    "Found close message, expected string as HELLO payload".to_string(),
                ))
            }
        };
        serde_json::from_str::<CoreEvent>(&text).map_err(|e| InvalidInput::Malformed(e.to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TryFrom<tokio_tungstenite::tungstenite::Message> for CoreEvent {
    type Error = InvalidInput;

    fn try_from(value: tokio_tungstenite::tungstenite::Message) -> Result<Self, Self::Error> {
        let gw_message = GatewayMessage::from(value);
        CoreEvent::try_from(gw_message)
    }
}

impl Hash for GatewayMessage {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
    }
}

/// A gateway close message, indicating why the connection is closing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CloseMessage {
    /// A numeric code, indicating a reason for why the connection was closed.
    pub code: CloseCode,
    /// An arbitrary reason string. Might further indicate why the connection was closed.
    pub reason: String,
}

/// Status code used to indicate why an endpoint is closing the WebSocket connection.
///
/// ## Credit
///
/// This code was adapted from the [tungstenite](https://docs.rs/tungstenite/latest/tungstenite/) crate,
/// which was originally licensed under both the MIT and Apache-2.0 licenses. These portions have been modified and are
/// incorporated into this file, which is licensed in its entirety under the Mozilla Public License 2.0 (MPL-2.0).
///
/// For the full terms of the MPL-2.0, see the `LICENSE` file in this repository or <https://www.mozilla.org/MPL/2.0/>.
///
/// ### Copyright Notice
///
/// Copyright (c) 2017 Alexey Galakhov  
/// Copyright (c) 2016 Jason Housley
///
/// ### Original Licensing Terms
///
/// The original source code was licensed under the MIT License and the Apache License, Version 2.0.
/// Copies of these licenses are provided in the `third_party/tungstenite/LICENSE-MIT` and
/// `third_party/tungstenite/LICENSE-APACHE` files of this repository for reference.
#[derive(Debug, Eq, PartialEq, Clone, Copy, PartialOrd, Ord, Hash)]
pub enum CloseCode {
    /// Indicates a normal closure, meaning that the purpose for
    /// which the connection was established has been fulfilled.
    Normal,
    /// Indicates that an endpoint is "going away", such as a server
    /// going down or a browser having navigated away from a page.
    Away,
    /// Indicates that an endpoint is terminating the connection due
    /// to a protocol error.
    Protocol,
    /// Indicates that an endpoint is terminating the connection
    /// because it has received a type of data it cannot accept (e.g., an
    /// endpoint that understands only text data MAY send this if it
    /// receives a binary message).
    Unsupported,
    /// Indicates that no status code was included in a closing frame. This
    /// close code makes it possible to use a single method, `on_close` to
    /// handle even cases where no close code was provided.
    Status,
    /// Indicates an abnormal closure. If the abnormal closure was due to an
    /// error, this close code will not be used. Instead, the `on_error` method
    /// of the handler will be called with the error. However, if the connection
    /// is simply dropped, without an error, this close code will be sent to the
    /// handler.
    Abnormal,
    /// Indicates that an endpoint is terminating the connection
    /// because it has received data within a message that was not
    /// consistent with the type of the message (e.g., non-UTF-8 \[RFC3629\]
    /// data within a text message).
    Invalid,
    /// Indicates that an endpoint is terminating the connection
    /// because it has received a message that violates its policy.  This
    /// is a generic status code that can be returned when there is no
    /// other more suitable status code (e.g., Unsupported or Size) or if there
    /// is a need to hide specific details about the policy.
    Policy,
    /// Indicates that an endpoint is terminating the connection
    /// because it has received a message that is too big for it to
    /// process.
    Size,
    /// Indicates that an endpoint (client) is terminating the
    /// connection because it has expected the server to negotiate one or
    /// more extension, but the server didn't return them in the response
    /// message of the WebSocket handshake.  The list of extensions that
    /// are needed should be given as the reason for closing.
    /// Note that this status code is not used by the server, because it
    /// can fail the WebSocket handshake instead.
    Extension,
    /// Indicates that a server is terminating the connection because
    /// it encountered an unexpected condition that prevented it from
    /// fulfilling the request.
    Error,
    /// Indicates that the server is restarting. A client may choose to reconnect,
    /// and if it does, it should use a randomized delay of 5-30 seconds between attempts.
    Restart,
    /// Indicates that the server is overloaded and the client should either connect
    /// to a different IP (when multiple targets exist), or reconnect to the same IP
    /// when a user has performed an action.
    Again,
    /// TLS related close codes
    Tls,
    /// Reserved close codes
    Reserved(u16),
    /// IANA (Internet Assigned Numbers Authority) reserved close codes
    Iana(u16),
    /// Library specific close codes. This means us!
    Library(u16),
    /// Bad connection! Bad connection! >:(
    Bad(u16),
}

impl std::fmt::Display for CloseCode {
    /// ## Credit
    ///
    /// This code was adapted from the [tungstenite](https://docs.rs/tungstenite/latest/tungstenite/) crate,
    /// which was originally licensed under both the MIT and Apache-2.0 licenses. These portions have been modified and are
    /// incorporated into this file, which is licensed in its entirety under the Mozilla Public License 2.0 (MPL-2.0).
    ///
    /// For the full terms of the MPL-2.0, see the `LICENSE` file in this repository or <https://www.mozilla.org/MPL/2.0/>.
    ///
    /// ### Copyright Notice
    ///
    /// Copyright (c) 2017 Alexey Galakhov  
    /// Copyright (c) 2016 Jason Housley
    ///
    /// ### Original Licensing Terms
    ///
    /// The original source code was licensed under the MIT License and the Apache License, Version 2.0.
    /// Copies of these licenses are provided in the `third_party/tungstenite/LICENSE-MIT` and
    /// `third_party/tungstenite/LICENSE-APACHE` files of this repository for reference.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let code: u16 = self.into();
        write!(f, "{code}")
    }
}

impl From<CloseCode> for u16 {
    /// ## Credit
    ///
    /// This code was adapted from the [tungstenite](https://docs.rs/tungstenite/latest/tungstenite/) crate,
    /// which was originally licensed under both the MIT and Apache-2.0 licenses. These portions have been modified and are
    /// incorporated into this file, which is licensed in its entirety under the Mozilla Public License 2.0 (MPL-2.0).
    ///
    /// For the full terms of the MPL-2.0, see the `LICENSE` file in this repository or <https://www.mozilla.org/MPL/2.0/>.
    ///
    /// ### Copyright Notice
    ///
    /// Copyright (c) 2017 Alexey Galakhov  
    /// Copyright (c) 2016 Jason Housley
    ///
    /// ### Original Licensing Terms
    ///
    /// The original source code was licensed under the MIT License and the Apache License, Version 2.0.
    /// Copies of these licenses are provided in the `third_party/tungstenite/LICENSE-MIT` and
    /// `third_party/tungstenite/LICENSE-APACHE` files of this repository for reference.
    fn from(code: CloseCode) -> u16 {
        match code {
            CloseCode::Normal => 1000,
            CloseCode::Away => 1001,
            CloseCode::Protocol => 1002,
            CloseCode::Unsupported => 1003,
            CloseCode::Status => 1005,
            CloseCode::Abnormal => 1006,
            CloseCode::Invalid => 1007,
            CloseCode::Policy => 1008,
            CloseCode::Size => 1009,
            CloseCode::Extension => 1010,
            CloseCode::Error => 1011,
            CloseCode::Restart => 1012,
            CloseCode::Again => 1013,
            CloseCode::Tls => 1015,
            CloseCode::Reserved(code) => code,
            CloseCode::Iana(code) => code,
            CloseCode::Library(code) => code,
            CloseCode::Bad(code) => code,
        }
    }
}

impl<'t> From<&'t CloseCode> for u16 {
    /// ## Credit
    ///
    /// This code was adapted from the [tungstenite](https://docs.rs/tungstenite/latest/tungstenite/) crate,
    /// which was originally licensed under both the MIT and Apache-2.0 licenses. These portions have been modified and are
    /// incorporated into this file, which is licensed in its entirety under the Mozilla Public License 2.0 (MPL-2.0).
    ///
    /// For the full terms of the MPL-2.0, see the `LICENSE` file in this repository or <https://www.mozilla.org/MPL/2.0/>.
    ///
    /// ### Copyright Notice
    ///
    /// Copyright (c) 2017 Alexey Galakhov  
    /// Copyright (c) 2016 Jason Housley
    ///
    /// ### Original Licensing Terms
    ///
    /// The original source code was licensed under the MIT License and the Apache License, Version 2.0.
    /// Copies of these licenses are provided in the `third_party/tungstenite/LICENSE-MIT` and
    /// `third_party/tungstenite/LICENSE-APACHE` files of this repository for reference.
    fn from(code: &'t CloseCode) -> u16 {
        (*code).into()
    }
}

impl From<u16> for CloseCode {
    /// ## Credit
    ///
    /// This code was adapted from the [tungstenite](https://docs.rs/tungstenite/latest/tungstenite/) crate,
    /// which was originally licensed under both the MIT and Apache-2.0 licenses. These portions have been modified and are
    /// incorporated into this file, which is licensed in its entirety under the Mozilla Public License 2.0 (MPL-2.0).
    ///
    /// For the full terms of the MPL-2.0, see the `LICENSE` file in this repository or <https://www.mozilla.org/MPL/2.0/>.
    ///
    /// ### Copyright Notice
    ///
    /// Copyright (c) 2017 Alexey Galakhov  
    /// Copyright (c) 2016 Jason Housley
    ///
    /// ### Original Licensing Terms
    ///
    /// The original source code was licensed under the MIT License and the Apache License, Version 2.0.
    /// Copies of these licenses are provided in the `third_party/tungstenite/LICENSE-MIT` and
    /// `third_party/tungstenite/LICENSE-APACHE` files of this repository for reference.
    fn from(code: u16) -> CloseCode {
        match code {
            1000 => Self::Normal,
            1001 => Self::Away,
            1002 => Self::Protocol,
            1003 => Self::Unsupported,
            1005 => Self::Status,
            1006 => Self::Abnormal,
            1007 => Self::Invalid,
            1008 => Self::Policy,
            1009 => Self::Size,
            1010 => Self::Extension,
            1011 => Self::Error,
            1012 => Self::Restart,
            1013 => Self::Again,
            1015 => Self::Tls,
            1..=999 => Self::Bad(code),
            1016..=2999 => Self::Reserved(code),
            3000..=3999 => Self::Iana(code),
            4000..=4999 => Self::Library(code),
            _ => Self::Bad(code),
        }
    }
}
