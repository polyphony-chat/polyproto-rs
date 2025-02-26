// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Debug;

use url::Url;

use crate::key::PrivateKey;
use crate::signature::Signature;

use super::Gateway;

#[cfg(not(feature = "wasm"))]
pub type GatewayBackend = tungstenite::TungsteniteBackend;
#[cfg(not(feature = "wasm"))]
/// The tungstenite gateway backend. Used on non-wasm targets.
pub mod tungstenite;
#[cfg(feature = "wasm")]
/// The wasm gateway backend. Used only on the wasm-target.
pub mod wasm;
#[cfg(feature = "wasm")]
pub type GatewayBackend = wasm::Backend;

/// Trait defining required functionality for a gateway backend.
pub trait BackendBehavior {
    /// Try and open a WebSocket connection to a [Gateway] server under a certain [Url].
    async fn connect<S, T>(url: &Url) -> GatewayResult<Gateway<S, T>>
    where
        S: Debug + Signature,
        <T as crate::key::PrivateKey<S>>::PublicKey: Debug,
        T: PrivateKey<S>;
}

pub type GatewayResult<T> = Result<T, Error>;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {}

pub enum GatewayMessage {
    Text(String),
    Binary(Vec<u8>),
    Close(Option<CloseMessage>),
}

pub struct CloseMessage {
    pub code: CloseCode,
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
    Tls,
    Reserved(u16),
    Iana(u16),
    Library(u16),
    Bad(u16),
}
