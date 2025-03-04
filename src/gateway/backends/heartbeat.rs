// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Duration;

use log::{debug, trace};
use serde_json::{from_str, json};
use tokio::select;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::types::gateway::{CoreEvent, MinifiedNumberRange, Payload};

use super::super::KILL_LOG_MESSAGE;
use super::{Closed, GatewayMessage};

#[derive(Debug)]
pub(crate) struct Heartbeat {
    task_handle: JoinHandle<()>,
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
                        let payload = match from_str::<CoreEvent>(&message) {
                            Ok(payload) => payload,
                            Err(_) => {trace
                                !("Payload couldn't be decoded as CoreEvent, ignoring it");
                                continue
                            },
                        };
                        match payload.d() {
                            crate::types::gateway::Payload::RequestHeartbeat => {
                                trace!("Gaetway server requested a manual heartbeat!");
                                Self::try_send_heartbeat(message_sender.clone(), &received_sequences, kill_send.clone(), 1).await
                            },
                            crate::types::gateway::Payload::HeartbeatAck(heartbeat_ack) => todo!(),
                            _ => continue
                        };
                    }
                }
            }
        });
        Self { task_handle }
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
                    MinifiedNumberRange::from(received_sequences)
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

    fn handle_reqeuest_heartbeat(&self, message_sender: watch::Sender<GatewayMessage>) {}
}
