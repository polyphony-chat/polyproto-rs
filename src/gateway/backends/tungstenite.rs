// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use futures_util::stream::StreamExt;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_tungstenite::{connect_async_tls_with_config, connect_async_with_config};

use crate::sealer::Glue;

use super::*;
#[derive(Debug)]
pub struct TungsteniteBackend {
    kill_send: broadcast::Sender<()>,
    kill_receive: broadcast::Receiver<()>,
    gateway_task: JoinHandle<Result<(), super::Error>>,
}

impl Glue for TungsteniteBackend {}

impl BackendBehavior for TungsteniteBackend {
    async fn connect<S, T>(url: &Url, token: String) -> GatewayResult<Gateway<S, T>>
    where
        S: Debug + Signature,
        <T as crate::key::PrivateKey<S>>::PublicKey: Debug,
        T: PrivateKey<S>,
    {
        let (stream, _) = match url.scheme() {
            "ws" => match connect_async_with_config(url, None, false).await {
                Ok(stream) => stream,
                Err(e) => return Err(Error::BackendError(e.to_string())),
            },
            "wss" => {
                let certs = webpki_roots::TLS_SERVER_ROOTS;
                let roots = rustls::RootCertStore {
                    roots: certs.iter().map(|cert| cert.to_owned()).collect(),
                };
                match connect_async_tls_with_config(
                    url,
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
        todo!()
    }

    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<GatewayMessage> {
        todo!()
    }

    async fn send(&self, value: GatewayMessage) -> Result<usize, SendError<GatewayMessage>> {
        todo!()
    }

    async fn disconnect(reason: Option<CloseMessage>) -> Result<(), Error> {
        todo!()
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
