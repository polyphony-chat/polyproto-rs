// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::Arc;

use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use log::{debug, trace};
use tokio::select;
use tokio::sync::{watch, Mutex};
use tokio_tungstenite::{connect_async_tls_with_config, connect_async_with_config};

use crate::gateway::{kill, KILL_LOG_MESSAGE};
use crate::sealer::Glue;
use crate::types::gateway::{CoreEvent, Payload};

use super::heartbeat::Heartbeat;
use super::*;

#[derive(Clone, Debug)]
/// A [Gateway] backend implementing [BackendBehavior], based on `tokio-tungstenite`. Works on most
/// architectures, with a notable exception being the `wasm32-unknown-unknown` target triple.
pub struct TungsteniteBackend {
    sender: tokio::sync::watch::Sender<GatewayMessage>,
}

impl TungsteniteBackend {
    /// Create a new instance of this backend.
    pub fn new() -> Self {
        Self {
            sender: watch::channel(GatewayMessage::Text(String::new())).0,
        }
    }
}

impl Default for TungsteniteBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Glue for TungsteniteBackend {}

impl BackendBehavior for TungsteniteBackend {
    async fn connect<S, T>(
        &self,
        session: Arc<Session<S, T>>,
        gateway_url: &Url,
    ) -> GatewayResult<Gateway<S, T>>
    where
        S: Debug + Signature,
        <T as crate::key::PrivateKey<S>>::PublicKey: Debug,
        T: PrivateKey<S>,
    {
        let (stream, _) = match gateway_url.scheme() {
            "ws" => match connect_async_with_config(gateway_url, None, false).await {
                Ok(stream) => stream,
                Err(e) => return Err(Error::BackendError(e.to_string())),
            },
            "wss" => {
                let certs = webpki_roots::TLS_SERVER_ROOTS;
                let roots = rustls::RootCertStore {
                    roots: certs.iter().map(|cert| cert.to_owned()).collect(),
                };
                match connect_async_tls_with_config(
                    gateway_url,
                    None,
                    false,
                    Some(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(
                        rustls::ClientConfig::builder()
                            .with_root_certificates(roots)
                            .with_no_client_auth(),
                    ))),
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(e) => return Err(Error::BackendError(e.to_string())),
                }
            }
            e => return Err(ConnectionError::ConnectionScheme(e.to_string()).into()),
        };
        let (mut split_sink, mut split_stream) = stream.split();
        let (kill_send, kill_receive) = watch::channel::<Closed>(Closed::Exhausted);
        // The received_message_sender sends messages received from the WebSocket server from inside
        // the task_handle to all receivers.
        let (received_message_sender, received_message_receiver) =
            watch::channel::<GatewayMessage>(GatewayMessage::Text(String::new()));
        let mut receive_task_kill_receive = kill_receive.clone();
        let receive_task_kill_send = kill_send.clone();
        let mut received_hello = false;
        let interval = Arc::new(Mutex::new(0u32));
        let interval_clone = interval.clone();
        let receiver_join_handle = tokio::spawn(async move {
            loop {
                select! {
                    _ = receive_task_kill_receive.changed() => {
                        trace!("{KILL_LOG_MESSAGE}");
                        receive_task_kill_receive.borrow_and_update();
                        break;
                    }
                    message_result = split_stream.next() => {
                        let tungstenite_message = match message_result {
                            Some(message_result) => match message_result  {
                                Ok(m) => m,
                                Err(e) => {
                                    kill!(receive_task_kill_send, debug, format!(r#"Received error as next message in receiver stream. Sending kill signal: {e}"#));
                                    break;
                                },
                            },
                            None => {
                                kill!(receive_task_kill_send, trace, r#"Received "None" as next message in receiver stream. Channel closed; sending kill signal"#);
                                break;
                            },
                        };
                        let message = GatewayMessage::from(tungstenite_message);
                        // Expect hello if we haven't received one yet
                        if !received_hello {
                            match message {
                                GatewayMessage::Text(text) => {
                                    let event = match serde_json::from_str::<CoreEvent>(&text) {
                                        Ok(e) => e,
                                        Err(_) => {
                                            kill!(receive_task_kill_send, info, "Server should have sent HELLO as first message. Cannot continue");
                                            break;
                                        }
                                    };
                                    match event.d() {
                                        Payload::Hello(hello) => {
                                            let mut interval = interval_clone.lock().await;
                                            *interval = hello.heartbeat_interval;
                                            drop(interval)
                                        }
                                        _ => {
                                            kill!(receive_task_kill_send, info, "Server should have sent HELLO as first message. Cannot continue");
                                            break;
                                        }
                                    }
                                },
                                _ => {
                                    kill!(receive_task_kill_send, info, "Server should have sent HELLO as first message. Cannot continue");
                                    break;
                                },
                            };
                            received_hello = true;
                        } else {
                            trace!("Received gateway message, updating receivers");
                            trace!("Message: {:?}", message);
                            match received_message_sender.send(message) {
                                Ok(_) => trace!("Updated all receivers"),
                                Err(e) => debug!("Failed to update receivers. Don't care though, we ball (task will not exit) {e}"),
                            }
                        }

                    }
                }
            }
        });
        let mut send_task_kill_receive = kill_receive.clone();
        let send_task_kill_send = kill_send.clone();
        // The sent_message_sender send messages from outside the gateway task into the gateway task,
        // where the task then forwards the message to the websocket server.
        let sent_message_sender = self.sender.clone();
        let mut sent_message_receiver = sent_message_sender.subscribe();
        let sender_join_handle = tokio::spawn(async move {
            loop {
                select! {
                    _ = send_task_kill_receive.changed() => {
                        trace!("{KILL_LOG_MESSAGE}");
                        send_task_kill_receive.borrow_and_update();
                        break;
                    }
                    _ = sent_message_receiver.changed() => {
                        let message = sent_message_receiver.borrow_and_update().clone();
                        match split_sink.send(tokio_tungstenite::tungstenite::Message::from(message)).await {
                            Ok(_) => trace!("Successfully sent message to server"),
                            Err(e) => {
                                kill!(send_task_kill_send, debug, format!(r#"Received error when sending message to server. Sending kill signal: {e}"#));
                                break;
                            },
                        };
                    }
                }
            }
        });
        let heartbeat_task = Heartbeat::spawn(
            kill_receive.clone(),
            kill_send.clone(),
            received_message_receiver.clone(),
            sent_message_sender.clone(),
            *interval.lock().await,
        );
        Ok(Gateway {
            session,
            send_channel: sent_message_sender,
            receive_channel: received_message_receiver,
            _kill_send: kill_send,
            _receiver_task: receiver_join_handle,
            _sender_task: sender_join_handle,
            _heartbeat_task: heartbeat_task,
        })
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<GatewayMessage> {
        self.sender.subscribe()
    }

    async fn send(&self, value: GatewayMessage) -> Result<(), SendError<GatewayMessage>> {
        self.sender.send(value)
    }

    async fn disconnect(
        &self,
        reason: Option<CloseMessage>,
    ) -> Result<(), SendError<GatewayMessage>> {
        self.sender.send(GatewayMessage::Close(reason))
    }
}

impl From<tokio_tungstenite::tungstenite::Message> for GatewayMessage {
    fn from(value: tokio_tungstenite::tungstenite::Message) -> Self {
        match value {
            tokio_tungstenite::tungstenite::Message::Text(utf8_bytes) => {
                Self::Text(utf8_bytes.to_string())
            }
            tokio_tungstenite::tungstenite::Message::Binary(bytes) => Self::Binary(bytes.to_vec()),
            tokio_tungstenite::tungstenite::Message::Ping(bytes) => Self::Binary(bytes.to_vec()),
            tokio_tungstenite::tungstenite::Message::Pong(bytes) => Self::Binary(bytes.to_vec()),
            tokio_tungstenite::tungstenite::Message::Close(close_frame) => {
                Self::Close(close_frame.map(|c| CloseMessage {
                    code: CloseCode::from(u16::from(c.code)),
                    reason: c.reason.to_string(),
                }))
            }
            tokio_tungstenite::tungstenite::Message::Frame(frame) => {
                Self::Binary(frame.into_payload().to_vec())
            }
        }
    }
}

impl From<GatewayMessage> for tokio_tungstenite::tungstenite::Message {
    fn from(value: GatewayMessage) -> Self {
        match value {
            GatewayMessage::Text(t) => Self::text(t),
            GatewayMessage::Binary(items) => Self::binary(items),
            GatewayMessage::Close(close_message) => Self::Close(close_message.map(
                |close_message| tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::from(
                        u16::from(close_message.code),
                    ),
                    reason: close_message.reason.into(),
                },
            )),
        }
    }
}
