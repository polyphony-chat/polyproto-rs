use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

use super::Payload;

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Heartbeat {
    #[serde_as(as = "DisplayFromStr")]
    pub from: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub to: u64,
    #[serde_as(as = "Vec<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub except: Vec<u64>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    #[serde_as(as = "DisplayFromStr")]
    pub heartbeat_interval: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Identify {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct NewSession {
    pub cert: String,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct ActorCertificateInvalidation {
    #[serde_as(as = "DisplayFromStr")]
    pub serial: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub invalid_since: u64,
    pub signature: String,
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
