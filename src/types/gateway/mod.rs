// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// Module defining gateway `d` payloads.
pub mod payload;

use serde::de::Error;
use serde_json::{from_str, json, Value};
use std::fmt::Debug;
use std::hash::Hash;

use payload::*;
use serde::de::Visitor;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A gateway event from the `core` namespace. [Documentation link](https://docs.polyphony.chat/Protocol%20Specifications/core/#321-gateway-event-payloads)
pub struct CoreEvent {
    /// [Namespace](https://docs.polyphony.chat/Protocol%20Specifications/core/#82-namespaces) context for this payload.
    pub n: String,
    /// Gateway Opcode indicating the type of payload.
    #[serde_as(as = "DisplayFromStr")]
    pub op: u16,
    /// The event data associated with this payload.
    pub d: Payload,
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Sequence number of the event, used for guaranteed, ordered delivery. This field is only received by clients and never sent to the server.
    pub s: Option<u64>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
/// A gateway event from any namespace. Can contain arbitrary data as its `d` payload.
pub struct AnyEvent {
    /// [Namespace](https://docs.polyphony.chat/Protocol%20Specifications/core/#82-namespaces) context for this payload.
    pub n: String,
    /// Gateway Opcode indicating the type of payload.
    #[serde_as(as = "DisplayFromStr")]
    pub op: u16,
    /// The data associated with this payload.
    pub d: Value,
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Sequence number of the event, used for guaranteed, ordered delivery. This field is only received by clients and never sent to the server.
    pub s: Option<u64>,
}

impl From<CoreEvent> for AnyEvent {
    fn from(value: CoreEvent) -> Self {
        Self {
            n: value.n,
            op: value.op,
            d: json!(value.d),
            s: value.s,
        }
    }
}

impl TryFrom<AnyEvent> for CoreEvent {
    type Error = serde_json::Error;

    fn try_from(value: AnyEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            n: value.n,
            op: value.op,
            d: from_str(value.d.to_string().as_str())?,
            s: value.s,
        })
    }
}

impl CoreEvent {
    /// Convert [Self] into an [AnyEvent]. Shorthand for `AnyEvent::from(self)`.
    pub fn into_any_event(self) -> AnyEvent {
        AnyEvent::from(self)
    }
}

impl AnyEvent {
    /// Try to convert [Self] into a [CoreEvent]. Shorthand for `CoreEvent::try_from(self)`.
    ///
    /// ## Errors
    ///
    /// The conversion will fail, if `self.d` is not a valid [Payload].
    pub fn try_into_core_event(self) -> Result<CoreEvent, serde_json::Error> {
        CoreEvent::try_from(self)
    }
}

#[repr(u16)]
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

impl From<Opcode> for u16 {
    fn from(value: Opcode) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for Opcode {
    type Error = crate::errors::InvalidInput;

    // TODO: i know this can be done better but i am incredibly sleep deprived and just happy to have it work
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Heartbeat,
            1 => Self::Hello,
            2 => Self::Identify,
            3 => Self::NewSession,
            4 => Self::ActorCertificateInvalidation,
            5 => Self::Resume,
            6 => Self::ServerCertificateChange,
            7 => Self::HeartbeatAck,
            8 => Self::ServiceChannel,
            9 => Self::ServiceChannelAck,
            10 => Self::Resumed,
            _ => {
                return Err(crate::errors::InvalidInput::Malformed(format!(
                    "value {value} is not a valid opcode"
                )))
            }
        })
    }
}

/// Type has a corresponding gateway opcode
pub trait HasOpcode: crate::sealer::Glue {
    /// Get the gateway opcode of this type
    fn opcode(&self) -> u16;
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Data (`d`) payload of a Gateway event.
pub enum Payload {
    /// The heartbeat event is sent by the client to the server to keep the WebSocket connection alive.
    /// The payload for the heartbeat event is a minified number list. Minified number lists are a
    /// `JSON` object with the fields `from`, `to`, and `except`. The `from` and `to` fields are
    /// strings representing a range of numbers. The `except` field is an array of strings
    /// representing numbers that are not included in the range.
    ///
    /// The range described by the `from` and to `fields` is a mathematical, closed interval
    Heartbeat(Heartbeat),
    /// The "Hello" event is sent by the server to the client upon establishing a connection.
    /// The `d` payload for a "Hello" event is an object containing a `heartbeat_interval` field,
    /// which specifies the interval in milliseconds at which the client should send heartbeat
    /// events to the server.
    Hello(Hello),
    /// The "identify" event is sent by the client to the server to let the server know which actor the client is.
    Identify(Identify),
    /// The "New Session" event is sent by the server to all sessions except the new one. The `d`
    /// payload of this event contains the ASCII-PEM encoded ID-Cert of the new session. You can
    /// find more information about the new session mechanism in [section 4.3.](https://docs.polyphony.chat/Protocol%20Specifications/core/#43-protection-against-misuse-by-malicious-home-servers)
    NewSession(NewSession),
    /// The actor certificate invalidation event is crucial to ensure that the client can detect
    /// and respond to changes in actor certificates. This prevents clients and servers from
    /// accepting outdated [IdCert]s. This event is only sent by servers if an early revocation of
    /// an actor ID-Cert occurs.
    ActorCertificateInvalidation(ActorCertificateInvalidation),
    /// When a client re-connects to a polyproto WebSocket gateway server, the client may send a
    /// resume event to the server instead of identifying. The resumed event sent by the server
    /// informs the client about everything the client has missed since their last active
    /// connection to the gateway.
    ///
    /// Servers may reject a clients' wish to resume, if the number of events that would need to be
    /// replayed is too high for the server to process. In this case, the request to resume is met
    /// with a close code of 4010 by the server and the connection is terminated.
    Resume(Resume),
    /// The server certificate change event notifies clients about a new server ID-Cert. The
    /// `d` payload of this event contains the ASCII-PEM encoded [IdCert] of the server.
    ServerCertificateChange(ServerCertificateChange),
    /// A heartbeat ACK contains events that the client has re-requested as part of their heartbeat
    /// message.
    ///
    /// As such, the field `d` in a heartbeat ack may be empty, but never not present. The `d` field
    /// contains an array of other gateway events. Heartbeat ACK payloads must not be present in
    /// this array, making recursion impossible.
    HeartbeatAck(HeartbeatAck),
    /// Service channels act like topics in a pub/sub system. They allow clients to subscribe to a
    /// specific topic and receive messages sent to that topic.
    ///
    /// Converting that analogy to polyproto, service channels allow clients to subscribe to gateway
    /// events of additional namespaces. Service channels allow a unified way of giving extensions
    /// access to WebSockets without having to initialize a separate WebSocket connection.
    ServiceChannel(ServiceChannel),
    /// Response to a [Payload::ServiceChannel] payload, indicating whether the
    /// action was successful or not. Clients should expect that the server sends a Service Channel
    /// payload indicating the closing of a channel.
    ServiceChannelAck(ServiceChannelAck),
    /// The "resumed" event contains all relevant events the client has missed.
    ///
    /// A set of "relevant events" is a set of events which meet both of the following conditions:
    /// 1. Each event in the set is intended to be received by the client
    /// 2. The set must contain the lowest possible amount of events necessary for the client to be
    ///    informed about everything that happened while they were disconnected.
    Resumed(Resumed),
}

impl crate::sealer::Glue for Payload {}

impl HasOpcode for Payload {
    fn opcode(&self) -> u16 {
        match self {
            Payload::Heartbeat(_) => Opcode::Heartbeat as u16,
            Payload::Hello(_) => Opcode::Heartbeat as u16,
            Payload::Identify(_) => Opcode::Heartbeat as u16,
            Payload::NewSession(_) => Opcode::Heartbeat as u16,
            Payload::ActorCertificateInvalidation(_) => Opcode::Heartbeat as u16,
            Payload::Resume(_) => Opcode::Heartbeat as u16,
            Payload::ServerCertificateChange(_) => Opcode::Heartbeat as u16,
            Payload::HeartbeatAck(_) => Opcode::Heartbeat as u16,
            Payload::ServiceChannel(_) => Opcode::Heartbeat as u16,
            Payload::ServiceChannelAck(_) => Opcode::Heartbeat as u16,
            Payload::Resumed(_) => Opcode::Heartbeat as u16,
        }
    }
}

impl Serialize for Payload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Payload::Heartbeat(heartbeat) => serializer.serialize_newtype_struct("d", heartbeat),
            Payload::Hello(hello) => serializer.serialize_newtype_struct("d", hello),
            Payload::Identify(identify) => serializer.serialize_newtype_struct("d", identify),
            Payload::NewSession(new_session) => {
                serializer.serialize_newtype_struct("d", new_session)
            }
            Payload::ActorCertificateInvalidation(actor_certificate_invalidation) => {
                serializer.serialize_newtype_struct("d", actor_certificate_invalidation)
            }
            Payload::Resume(resume) => serializer.serialize_newtype_struct("d", resume),
            Payload::ServerCertificateChange(server_certificate_change) => {
                serializer.serialize_newtype_struct("d", server_certificate_change)
            }
            Payload::HeartbeatAck(heartbeat_ack) => {
                serializer.serialize_newtype_struct("d", heartbeat_ack)
            }
            Payload::ServiceChannel(service_channel) => {
                serializer.serialize_newtype_struct("d", service_channel)
            }
            Payload::ServiceChannelAck(service_channel_ack) => {
                serializer.serialize_newtype_struct("d", service_channel_ack)
            }
            Payload::Resumed(resumed) => serializer.serialize_newtype_struct("d", resumed),
        }
    }
}

impl<'de> Deserialize<'de> for CoreEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        {
            struct EventVisitor;

            impl<'de> Visitor<'de> for EventVisitor {
                type Value = CoreEvent;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a Payload with a field `d` and a field `op`")
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut maybe_d = None;
                    let mut maybe_opcode = None;
                    let mut maybe_s = None;

                    while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                        dbg!(&key);
                        dbg!(&value);
                        if key == "d" {
                            maybe_d = Some(value);
                        } else if key == "op" {
                            maybe_opcode = Some(value)
                        } else if key == "s" {
                            maybe_s = Some(value);
                        }
                    }

                    let d_serde_value = match maybe_d {
                        Some(value) => value,
                        None => return Err(A::Error::missing_field("d")),
                    };
                    let op_serde_value = match maybe_opcode {
                        Some(value) => value,
                        None => return Err(A::Error::missing_field("op")),
                    };
                    let integer_maybe_opcode: u16 =
                        match up_to_64_bit_uint_from_value(&op_serde_value) {
                            Ok(o) => o,
                            Err(e) => return Err(A::Error::custom(e)),
                        };
                    let op = Opcode::try_from(integer_maybe_opcode).map_err(A::Error::custom)?;

                    let s = match maybe_s {
                        Some(s) => Some(
                            up_to_64_bit_uint_from_value::<u64>(&s).map_err(A::Error::custom)?,
                        ),
                        None => None,
                    };

                    let d = match op {
                        Opcode::Heartbeat => Payload::Heartbeat(
                            serde_json::from_value::<Heartbeat>(d_serde_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::Hello => Payload::Hello(
                            serde_json::from_value::<Hello>(d_serde_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::Identify => Payload::Identify(
                            serde_json::from_value::<Identify>(d_serde_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::NewSession => Payload::NewSession(
                            serde_json::from_value::<NewSession>(d_serde_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::ActorCertificateInvalidation => {
                            Payload::ActorCertificateInvalidation(
                                serde_json::from_value::<ActorCertificateInvalidation>(
                                    d_serde_value.clone(),
                                )
                                .map_err(A::Error::custom)?,
                            )
                        }
                        Opcode::Resume => Payload::Resume(
                            serde_json::from_value::<Resume>(d_serde_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::ServerCertificateChange => Payload::ServerCertificateChange(
                            serde_json::from_value::<ServerCertificateChange>(
                                d_serde_value.clone(),
                            )
                            .map_err(A::Error::custom)?,
                        ),
                        Opcode::HeartbeatAck => Payload::HeartbeatAck(
                            serde_json::from_value::<HeartbeatAck>(d_serde_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::ServiceChannel => Payload::ServiceChannel(
                            serde_json::from_value::<ServiceChannel>(d_serde_value.clone())
                                .map_err(A::Error::custom)?,
                        ),

                        Opcode::ServiceChannelAck => Payload::ServiceChannelAck(
                            serde_json::from_value::<ServiceChannelAck>(d_serde_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::Resumed => Payload::Resumed(
                            serde_json::from_value::<Resumed>(d_serde_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                    };

                    let event = CoreEvent {
                        n: "core".to_string(),
                        op: op.into(),
                        d,
                        s,
                    };
                    Ok(event)
                }
            }

            deserializer.deserialize_map(EventVisitor)
        }
    }
}

/// Attempts to convert a value into an integer type, provided that the source value is up to 64 bits
/// in size.
///
/// This function will attempt to convert the provided `Value` into an instance of the specified type `T`.
/// The conversion can be done from either a `u64` value or by parsing a string representing a `u64` value.
///
/// # Errors
///
/// This function returns an error in the following cases:
///
/// - If the input `Value` is neither a `String` nor an `Integer`, the function will return an error with a message indicating that it expected either a `String` or an `Integer`.
/// - If the conversion from `u64` to the target type `T` fails, the function will return an error with a message describing the conversion failure.
/// - If the input string is not a valid representation of a `u64`, the function will return an error with a message indicating that it encountered a conversion error when parsing the string.
fn up_to_64_bit_uint_from_value<T: TryFrom<u64>>(
    value: &Value,
) -> Result<T, crate::errors::InvalidInput>
where
    <T as std::convert::TryFrom<u64>>::Error: Debug,
{
    match value {
        // extract this function into subfunction that can take u16 or u64
        Value::Number(num) => {
            let num_u64 = match num.as_u64() {
                Some(u) => u,
                None => {
                    return Err(crate::errors::InvalidInput::Malformed(
                        "Integer is larger than 64 bits".to_string(),
                    ))
                }
            };
            match T::try_from(num_u64) {
                Ok(converted_value) => Ok(converted_value),
                Err(e) => Err(crate::errors::InvalidInput::Malformed(format!(
                    "Conversion error from number: {:?}",
                    e
                ))),
            }
        }
        Value::String(str) => match str.parse::<u64>() {
            Ok(converted_u64) => T::try_from(converted_u64).map_err(|e| {
                crate::errors::InvalidInput::Malformed(format!(
                    "Conversion error from string: {:?}",
                    e
                ))
            }),
            Err(e) => Err(crate::errors::InvalidInput::Malformed(format!(
                "Conversion error from string: {:?}",
                e
            ))),
        },
        other => Err(crate::errors::InvalidInput::Malformed(format!(
            "Expected String or Integer, found value {:?}",
            other
        ))),
    }
}
