// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Duration;

use log::{debug, trace, warn};
use serde_json::{from_str, json};
use tokio::select;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::types::gateway::{AnyEvent, CoreEvent, Payload};

use super::super::KILL_LOG_MESSAGE;
use super::{Closed, GatewayMessage};

#[derive(Debug)]
pub(crate) struct Heartbeat {
    _task_handle: JoinHandle<()>,
}

impl Heartbeat {
    pub(crate) fn spawn(
        mut kill_receive: watch::Receiver<Closed>,
        kill_send: watch::Sender<Closed>,
        mut message_receiver: watch::Receiver<GatewayMessage>,
        message_sender: watch::Sender<GatewayMessage>,
        interval: u32,
    ) -> Self {
        let task_handle = tokio::spawn(async move {
            let mut _sleep = Box::pin(tokio::time::sleep(Duration::from_secs(interval as u64)));
            let mut received_sequences = Vec::<u64>::new();
            loop {
                select! {
                    _ = &mut _sleep => {
                        trace!("Time to send another heartbeat!");
                        _sleep = Box::pin(tokio::time::sleep(Duration::from_secs(interval as u64)));
                        received_sequences.dedup();
                        Self::try_send_heartbeat(message_sender.clone(), &received_sequences, kill_send.clone(), 1).await;
                        received_sequences.shrink_to_fit();
                        continue;
                    }
                    _ = kill_receive.changed() => {
                        trace!("{KILL_LOG_MESSAGE}");
                        kill_receive.borrow_and_update();
                        break;
                    }
                    _ = message_receiver.changed() => {
                        let message = message_receiver.borrow_and_update().clone();
                        let message = match message {
                            GatewayMessage::Text(t) => t,
                            _ => continue // Non-text messages cannot be gateway payloads relevant to this code, so we skip
                        };
                        let any_payload = match from_str::<AnyEvent>(&message) {
                            Ok(payload) => payload,
                            Err(_) => {
                            trace!("This payload is not a valid AnyEvent, ignoring it");
                                continue
                            },
                        };
                        if let Some(s) = any_payload.s { received_sequences.push(s) }
                        let any_payload_namespace = {
                            if any_payload.n.len() > 64 {
                                warn!(r#"Received a payload with namespace "{}", which has a namespace of over 64 characters in length! This is technically not polyproto compliant (see section 8.2 of the protocol definition). In the future, such events might not be processed at all, or simply lead to an error."#, any_payload.n);
                                "very_long_namespace".to_string()
                            } else {
                                any_payload.n.clone()
                            }
                        };
                        let any_payload_opcode = any_payload.op;
                        let core_payload = match CoreEvent::try_from(any_payload) {
                            Ok(p) => p,
                            Err(_) => {
                                trace!(r#"Payload with namespace "{}" and opcode {} does not seem to have valid CoreEvent data. Assuming it is not a manual heartbeat request and continuing."#, any_payload_namespace, any_payload_opcode);
                                continue;
                            }
                        };
                        match core_payload.d() {
                            crate::types::gateway::Payload::RequestHeartbeat => {
                                trace!("Gateway server requested a manual heartbeat!");
                                received_sequences.dedup();
                                Self::try_send_heartbeat(message_sender.clone(), &received_sequences, kill_send.clone(), 1).await
                            },
                            _ => continue
                        };
                    }
                }
            }
        });
        Self {
            _task_handle: task_handle,
        }
    }

    /// Attempts to send a heartbeat to the gateway. Will re-try sending the heartbeat up to 6 more times
    /// before giving up. Kills the gateway task when giving up, by sending a message through `kill_send`.
    async fn try_send_heartbeat(
        message_sender: watch::Sender<GatewayMessage>,
        received_sequences: &Vec<u64>,
        kill_send: watch::Sender<Closed>,
        attempt: u8,
    ) {
        if attempt > 5 {
            debug!("Tried sending heartbeat more than 5 times - never succeeded. Killing gateway");
            match kill_send.send(Closed::Error("No response on heartbeat".to_string())) {
                Ok(_) => trace!("Sent kill signal successfully"),
                Err(kill_error) => trace!(
                    "Sent kill signal, received error. Shutting down regardless: {kill_error}"
                ),
            };
            return;
        }
        if attempt != 0 {
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }
        let message = GatewayMessage::Text(
            json!(CoreEvent::new(
                Payload::Heartbeat(crate::types::gateway::payload::Heartbeat::from(
                    received_sequences
                )),
                None
            ))
            .to_string(),
        );
        let send_result = message_sender.send(message);
        match send_result {
            Ok(_) => (),
            Err(e) => {
                debug!("Sending heartbeat to gateway failed, retrying: {e}");
                Box::pin(Self::try_send_heartbeat(
                    message_sender,
                    received_sequences,
                    kill_send,
                    attempt + 1,
                ))
                .await
            }
        };
    }
}
