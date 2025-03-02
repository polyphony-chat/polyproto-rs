// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use log::trace;
use serde_json::from_str;
use tokio::select;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::types::gateway::CoreEvent;

use super::super::KILL_LOG_MESSAGE;
use super::GatewayMessage;

#[derive(Debug)]
pub(crate) struct Heartbeat {
    task_handle: JoinHandle<()>,
    packet_numbers: Vec<u64>,
}

impl Heartbeat {
    pub(crate) fn spawn(
        mut kill_receive: watch::Receiver<()>,
        kill_send: watch::Sender<()>,
        mut message_receiver: watch::Receiver<GatewayMessage>,
        message_sender: watch::Sender<GatewayMessage>,
    ) -> Self {
        let task_handle = tokio::spawn(async move {
            loop {
                select! {
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
                    }
                }
            }
        });
        todo!()
    }
}
