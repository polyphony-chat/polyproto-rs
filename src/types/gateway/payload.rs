use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

use crate::types::FederationId;

use super::Payload;

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// Sent by clients to the server to keep the WebSocket connection alive.
///
/// ## Reference
///
/// See sections [3.2.3.8](https://docs.polyphony.chat/Protocol%20Specifications/core/#3238-heartbeat-and-heartbeat-ack-events)
/// or [3.2.2](https://docs.polyphony.chat/Protocol%20Specifications/core/#322-heartbeats) of the
/// polyproto specification.
pub struct Heartbeat {
    #[serde_as(as = "DisplayFromStr")]
    /// The lowest received sequence number.
    pub from: u64,
    #[serde_as(as = "DisplayFromStr")]
    /// The highest received sequence number.
    pub to: u64,
    #[serde_as(as = "Vec<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    /// Sequence numbers in range `> from` and `< to`, which were not received by the client.
    pub except: Vec<u64>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// Sent by the server upon establishing a WebSocket connection.
///
/// ## Reference
///
/// See section [3.2.3.1](https://docs.polyphony.chat/Protocol%20Specifications/core/#3231-hello-event)
/// of the polyproto specification.
pub struct Hello {
    /// Heartbeat interval, in milliseconds
    #[serde_as(as = "DisplayFromStr")]
    pub heartbeat_interval: u32,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Whether there is an unfinished migration which can be resumed.
    ///
    /// ## Warning
    ///
    /// Read [security information regarding this object](https://docs.polyphony.chat/Protocol%20Specifications/core/#:~:text=of%20the%20migration.-,danger,-User-operated%20clients)
    /// before working with it.
    pub active_migration: Option<ActiveMigration>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// Supplementary information about an unfinished, resumeable migration process.
pub struct ActiveMigration {
    /// Migration source; Federation ID
    pub from: FederationId,
    /// Migration target; Federation ID
    pub to: FederationId,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// Identifying information about the client, namely a session token.
pub struct Identify {
    /// Session token.
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// Information about a new session that has logged in on the server.
///
/// ## Reference
///
/// See chapters [3.2.3.4](https://docs.polyphony.chat/Protocol%20Specifications/core/#3234-new-session-event)
/// and [4.3](https://docs.polyphony.chat/Protocol%20Specifications/core/#43-protection-against-misuse-by-malicious-home-servers)
/// of the polyproto specification.
pub struct NewSession {
    /// PEM encoded certificate of the new session
    pub cert: String,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// Information from a server informing clients about the fact that an actor certificate has been
/// prematurely revoked.
// TODO this seems useless. should likely be an updated certificate instead.
pub struct ActorCertificateInvalidation {
    #[serde(flatten)]
    pub certificate: CachedIdCert,
}

#[serde_as]
#[derive(Debug, Copy, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Resume {
    #[serde_as(as = "DisplayFromStr")]
    pub s: u64,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct ServerCertificateChange {
    pub cert: String,
    #[serde_as(as = "DisplayFromStr")]
    pub old_invalid_since: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
#[serde(transparent)]
pub struct HeartbeatAck {
    pub inner: Vec<Payload>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct ServiceChannel {
    pub action: ServiceChannelAction,
    pub service: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Debug)]
#[serde(rename_all = "camelCase")]
pub enum ServiceChannelAction {
    Subscribe,
    Unsubscribe,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct ServiceChannelAck {
    pub action: ServiceChannelAction,
    pub service: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
#[serde(transparent)]
pub struct Resumed {
    pub inner: Vec<Payload>,
}
