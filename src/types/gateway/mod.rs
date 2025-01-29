/// Module defining gateway `d` payloads.
pub mod payload;

use payload::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A generic gateway event. [Documentation link](https://docs.polyphony.chat/Protocol%20Specifications/core/#321-gateway-event-payloads)
pub struct Event<T> {
    /// [Namespace](https://docs.polyphony.chat/Protocol%20Specifications/core/#82-namespaces) context for this payload.
    pub n: String,
    /// Gateway Opcode indicating the type of payload.
    pub op: u16,
    /// The event data associated with this payload.
    pub d: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Sequence number of the event, used for guaranteed, ordered delivery. This field is only received by clients and never sent to the server.
    pub s: Option<u64>,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
/// Gateway Opcode indicating the type of a payload.
pub enum Opcode {
    /// Keep alive for the WebSocket session.
    Heartbeat = 0,
    /// Received upon establishing a connection.
    Hello = 1,
    /// Identify to the server.
    Identify = 2,
    /// Received by all sessions except the new one.
    NewSession = 3,
    /// An actor certificate has been invalidated. Sent to server when an actor invalidates one of their certificates.
    ActorCertificateInvalidation = 4,
    /// Request the replaying events after re-connecting.
    Resume = 5,
    /// Received when the server's certificate changed.
    ServerCertificateChange = 6,
    /// Acknowledgement of a heartbeat
    HeartbeatAck = 7,
    /// Open or close a service channel.
    ServiceChannel = 8,
    /// Acknowledgement of a service channel event.
    ServiceChannelAck = 9,
    /// Replayed events.
    Resumed = 10,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Data (`d`) payload of a Gateway event.
pub enum Payload {
    Heartbeat(Heartbeat) = Opcode::Heartbeat as u8,
    Hello(Hello) = Opcode::Hello as u8,
    Identify(Identify) = Opcode::Identify as u8,
    NewSession(NewSession) = Opcode::NewSession as u8,
    ActorCertificateInvalidation(ActorCertificateInvalidation) =
        Opcode::ActorCertificateInvalidation as u8,
    Resume(Resume) = Opcode::Resume as u8,
    ServerCertificateChange(ServerCertificateChange) = Opcode::ServerCertificateChange as u8,
    HeartbeatAck(HeartbeatAck) = Opcode::HeartbeatAck as u8,
    ServiceChannel(ServiceChannel) = Opcode::ServiceChannel as u8,
    ServiceChannelAck(ServiceChannelAck) = Opcode::ServiceChannelAck as u8,
    Resumed(Resumed) = Opcode::Resumed as u8,
}
