/// Module defining gateway `d` payloads.
pub mod payload;

use serde::de::{Error, Expected};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::marker::PhantomData;

use payload::*;
use serde::de::Visitor;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
// TODO: Needs custom deserializer to deserialize `d` based on opcode
/// A generic gateway event. [Documentation link](https://docs.polyphony.chat/Protocol%20Specifications/core/#321-gateway-event-payloads)
pub struct Event {
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

trait Glue {}

pub trait HasOpcode: Glue {
    fn opcode(&self) -> u16;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Data (`d`) payload of a Gateway event.
pub enum Payload {
    Heartbeat(Heartbeat),
    Hello(Hello),
    Identify(Identify),
    NewSession(NewSession),
    ActorCertificateInvalidation(ActorCertificateInvalidation),
    Resume(Resume),
    ServerCertificateChange(ServerCertificateChange),
    HeartbeatAck(HeartbeatAck),
    ServiceChannel(ServiceChannel),
    ServiceChannelAck(ServiceChannelAck),
    Resumed(Resumed),
}

impl Glue for Payload {}

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

// TODO this is cool n all but i need this for Event not for Payload :  ) ) )) ) ) )) ) )
impl<'de> Deserialize<'de> for Payload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        {
            struct PayloadVisitor;

            impl<'de> Visitor<'de> for PayloadVisitor {
                type Value = Payload;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a Payload with a field `d` and a field `op`")
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut maybe_d = None;
                    let mut maybe_opcode = None;

                    while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                        dbg!(&key);
                        dbg!(&value);
                        if key == "d" {
                            maybe_d = Some(value);
                        } else if key == "op" {
                            maybe_opcode = Some(value)
                        }
                    }

                    let d_value = match maybe_d {
                        Some(value) => value,
                        None => return Err(A::Error::missing_field("d")),
                    };
                    let op_value = match maybe_opcode {
                        Some(value) => value,
                        None => return Err(A::Error::missing_field("op")),
                    };
                    let integer_maybe_opcode = match op_value {
                        Value::Number(num) => {
                            let num_u64 = match num.as_u64() {
                                Some(u) => u,
                                None => {
                                    return Err(A::Error::custom(format!(
                                        "provided opcode {} is not an unsigned, 16 bit integer",
                                        num
                                    )))
                                }
                            };
                            match u16::try_from(num_u64) {
                                Ok(actual_opcode) => actual_opcode,
                                Err(e) => return Err(A::Error::custom(e)),
                            }
                        }
                        Value::String(str) => match str.parse::<u16>() {
                            Ok(actual_opcode) => actual_opcode,
                            Err(e) => return Err(A::Error::custom(e)),
                        },
                        other => {
                            return Err(A::Error::invalid_type(
                                serde::de::Unexpected::Other(&format!("{}", other)),
                                &"String or integer",
                            ))
                        }
                    };

                    let opcode =
                        Opcode::try_from(integer_maybe_opcode).map_err(A::Error::custom)?;

                    Ok(match opcode {
                        Opcode::Heartbeat => Payload::Heartbeat(
                            serde_json::from_value::<Heartbeat>(d_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::Hello => Payload::Hello(
                            serde_json::from_value::<Hello>(d_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::Identify => Payload::Identify(
                            serde_json::from_value::<Identify>(d_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::NewSession => Payload::NewSession(
                            serde_json::from_value::<NewSession>(d_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::ActorCertificateInvalidation => {
                            Payload::ActorCertificateInvalidation(
                                serde_json::from_value::<ActorCertificateInvalidation>(
                                    d_value.clone(),
                                )
                                .map_err(A::Error::custom)?,
                            )
                        }
                        Opcode::Resume => Payload::Resume(
                            serde_json::from_value::<Resume>(d_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::ServerCertificateChange => Payload::ServerCertificateChange(
                            serde_json::from_value::<ServerCertificateChange>(d_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::HeartbeatAck => Payload::HeartbeatAck(
                            serde_json::from_value::<HeartbeatAck>(d_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::ServiceChannel => Payload::ServiceChannel(
                            serde_json::from_value::<ServiceChannel>(d_value.clone())
                                .map_err(A::Error::custom)?,
                        ),

                        Opcode::ServiceChannelAck => Payload::ServiceChannelAck(
                            serde_json::from_value::<ServiceChannelAck>(d_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                        Opcode::Resumed => Payload::Resumed(
                            serde_json::from_value::<Resumed>(d_value.clone())
                                .map_err(A::Error::custom)?,
                        ),
                    })
                }
            }

            deserializer.deserialize_map(PayloadVisitor)
        }
    }
}
