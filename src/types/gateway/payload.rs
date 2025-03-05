// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

use super::Payload;

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// The heartbeat event is sent by the client to the server to keep the WebSocket connection alive.
/// The payload for the heartbeat event is a minified number list. Minified number lists are a JSON
/// object with the fields `from`, `to`, and `except`. The `from` and `to` fields are strings representing a
/// range of numbers. The `except` field is an array of strings representing numbers that are not
/// included in the range.
///
/// [Source](https://docs.polyphony.chat/Protocol%20Specifications/core/#3238-heartbeat-and-heartbeat-ack-events)
pub struct Heartbeat {
    #[serde_as(as = "DisplayFromStr")]
    /// The lowest received sequence number in this heartbeat interval
    pub from: u64,
    #[serde_as(as = "DisplayFromStr")]
    /// The highest received sequence number in this heartbeat interval
    pub to: u64,
    #[serde_as(as = "Vec<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    /// All sequence numbers `s` `from > s > to` which were not received this heartbeat interval.
    pub except: Vec<u64>,
}

impl Heartbeat {
    /// Create a new [Self] from a slice of sequence numbers.
    ///
    /// ## Performance
    ///
    /// Since this uses `impl From<&Vec<u64>> for Heartbeat`, this currently performs an allocation.
    /// Sad, I know, but as of writing this I am busy with getting everything ready for the public beta
    /// release of polyproto, and I do not have time to spend on premature optimization. Feel free to
    /// open a pull request, though.
    ///
    /// This operation performs best if the slice is ordered. `.sort()` is called on an owned version
    /// of the slice, which has `O(n*log(n))` performance on an unsorted vec (iirc).
    pub fn from_sequence_numbers(seq: &[u64]) -> Self {
        Heartbeat::from(&seq.to_vec())
    }
}

impl From<&Vec<u64>> for Heartbeat {
    fn from(value: &Vec<u64>) -> Self {
        if value.is_empty() {
            return Self {
                from: 0,
                to: 0,
                except: Vec::new(),
            };
        }
        if value.len() == 1 {
            return Self {
                from: value[0],
                to: value[0],
                except: Vec::new(),
            };
        }
        let mut min = value[0];
        let mut max = value[0];
        for item in value.iter() {
            if *item < min {
                min = *item;
            } else if *item > max {
                max = *item
            }
        }
        let mut ordered_values = value.clone();
        ordered_values.sort();

        let mut prev;
        let mut current;
        let mut missing = Vec::<u64>::new();

        for (index, value) in ordered_values.iter().enumerate() {
            if index.checked_sub(1).is_none() {
                continue;
            }
            prev = ordered_values.get(index - 1).copied();
            current = *value;

            if prev.is_none() {
                continue;
            }

            let some_prev = prev.unwrap();

            if current - some_prev > 1 {
                let mut difference = current - some_prev - 1;
                while difference != 0 {
                    missing.push(current - difference);
                    difference -= 1;
                }
            }
        }

        Heartbeat {
            from: min,
            to: max,
            except: missing,
        }
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// The "Hello" event is sent by the server to the client upon establishing a connection. The
/// payload for a "Hello" event is an object containing a `heartbeat_interval` field, which specifies
/// the interval in milliseconds at which the client should send heartbeat events to the server.
pub struct Hello {
    #[serde_as(as = "DisplayFromStr")]
    /// The interval in milliseconds at which the client should send heartbeat events to the server.
    pub heartbeat_interval: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// The "identify" event is sent by the client to the server to let the server know which actor the client is.
pub struct Identify {
    /// A session token issued by the server, identifying the session the client wants to connect with.
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// The "New Session" event is sent by the server to all sessions except the new one. The payload
/// of this event contains the ASCII-PEM encoded ID-Cert of the new session. You can find more
/// information about the new session mechanism in [section 4.3.](https://docs.polyphony.chat/Protocol%20Specifications/core/#43-protection-against-misuse-by-malicious-home-servers)
pub struct NewSession {
    /// ASCII-PEM encoded ID-Cert of the new session.
    pub cert: String,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// The actor certificate invalidation event is crucial to ensure that the client can detect and
/// respond to changes in actor certificates. This prevents clients and servers from accepting
/// outdated ID-Certs. This event is only sent by servers if an [early revocation of an actor
/// ID-Cert](https://docs.polyphony.chat/Protocol%20Specifications/core/#614-early-revocation-of-id-certs) occurs.
pub struct ActorCertificateInvalidation {
    #[serde_as(as = "DisplayFromStr")]
    /// The serial number of the invalidated ID-Cert
    pub serial: u64,
    #[serde_as(as = "DisplayFromStr")]
    /// UNIX timestamp of the point in time where this ID-Cert became invalid on
    pub invalid_since: u64,
    /// Signature of a string concatenation of the `invalidSince` timestamp and the serial number,
    /// in that order. Clients must verify this signature, verifying that the signature was generated
    /// by the private key of the revoked certificate.
    pub signature: String,
}

#[serde_as]
#[derive(Debug, Copy, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// When a client re-connects to a polyproto WebSocket gateway server, the client may send a resume
/// event to the server instead of identifying. The resumed event sent by the server informs the
/// client about everything the client has missed since their last active connection to the gateway.
pub struct Resume {
    #[serde_as(as = "DisplayFromStr")]
    /// Sequence number of the last event received by the client; aka. "Where to receive from".
    pub s: u64,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// The server certificate change event notifies clients about a new server ID-Cert.
/// The payload of this event contains the ASCII-PEM encoded ID-Cert of the server.
pub struct ServerCertificateChange {
    /// ASCII-PEM encoded server ID-Cert. The server ID-Cert is self-signed.
    pub cert: String,
    #[serde_as(as = "DisplayFromStr")]
    /// A UNIX timestamp indicating when the old server ID-Cert became invalid.
    pub old_invalid_since: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
#[serde(transparent)]
/// A heartbeat ACK contains events that the client has re-requested as part of their heartbeat message.
/// As such, the field `d` in a heartbeat ack may be empty, but never not present. The `d`
/// field contains an array of other gateway events. Heartbeat ACK payloads must not be present
/// in this array, making recursion impossible.
pub struct HeartbeatAck {
    /// Re-requested [Payload]s.
    pub inner: Vec<Payload>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// Service channels act like topics in a pub/sub system. They allow clients to subscribe to a
/// specific topic and receive messages sent to that topic.
///
/// Converting that analogy to polyproto, service channels allow clients to subscribe to gateway
/// events of additional namespaces. Service channels allow a unified way of giving extensions
/// access to WebSockets without having to initialize a separate WebSocket connection.
pub struct ServiceChannel {
    /// The action to perform on the service channel.
    pub action: ServiceChannelAction,
    /// The name of a polyproto service.
    pub service: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Debug)]
#[serde(rename_all = "camelCase")]
/// The action to perform on a service channel.
pub enum ServiceChannelAction {
    /// Subscribe to a service channel.
    Subscribe,
    /// Unsubscribe from a service channel.
    Unsubscribe,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
/// When sending a [ServiceChannelAction], the server must respond with a Service Channel ACK event
/// payload, indicating whether the action was successful or not. Clients should expect that the
/// server sends a Service Channel payload indicating the closing of a channel.
pub struct ServiceChannelAck {
    /// The action to perform on the service channel.
    pub action: ServiceChannelAction,
    /// The polyproto service that was specified in the opcode 8 request
    pub service: String,
    /// Whether the action was successful or not.
    pub success: bool,
    /// Only present if `success` is `false`. A message indicating why the action failed.
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
#[serde(transparent)]
/// The "resumed" event contains all relevant events the client has missed.
pub struct Resumed {
    /// Re-requested events.
    pub inner: Vec<Payload>,
}
