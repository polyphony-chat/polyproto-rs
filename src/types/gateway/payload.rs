// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
        let mut min = 0;
        let mut max = 0;
        for item in value.iter() {
            if *item < min {
                min = *item;
            } else if *item > max {
                max = *item
            }
        }
        let mut ordered_values = value.clone();
        ordered_values.sort();

        let mut prev = None;
        let mut next = 0u64;
        let mut missing = Vec::<u64>::new();

        for value in ordered_values.iter() {
            if prev.is_none() {
                prev = Some(*value);
            } else {
                next = *value;
            }

            let some_prev = prev.unwrap();

            if next - some_prev > 1 {
                let mut difference = next - some_prev;
                while difference != 0 {
                    missing.push(difference);
                    difference -= 1;
                }
            }

            prev = Some(next);
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
