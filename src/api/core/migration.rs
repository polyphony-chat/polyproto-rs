// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use super::*;
mod registration_required {
    use http::StatusCode;
    use reqwest::multipart::Form;
    use serde::Serialize;
    use serde_json::json;

    use crate::api::{P2RequestBuilder, SendsRequest, matches_status_code};
    use crate::types::keytrial::KeyTrialResponse;
    #[allow(deprecated)]
    use crate::types::p2_export::P2Export;

    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
        /// Import a `P2Export` file. `messages` in this file must have been re-signed to the current actor.
        /// Only messages classified as
        /// ["Information not tied to a specific context"](https://docs.polyphony.chat/Protocol%20Specifications/core/#:~:text=Example%3A%20Information%20not,without%0Aany%20issues.)
        /// can be imported.
        pub async fn import_data_to_server<M: Serialize>(
            &self,
            sensitive_solution: &str,
            data: P2Export<M>,
        ) -> HttpResult<()> {
            let endpoint = self.instance_url.join("/.p2/core/v1/migration/data/")?;
            let request = self
                .client
                .client
                .request(IMPORT_DATA.method, endpoint)
                .header("X-P2-Sensitive-Solution", sensitive_solution)
                .multipart(Form::try_from(data).map_err(|e| RequestError::Custom {
                    reason: e.to_string(),
                })?);

            let response = request.send().await?;
            matches_status_code(
                &[
                    StatusCode::ACCEPTED,
                    StatusCode::CREATED,
                    StatusCode::NO_CONTENT,
                ],
                response.status(),
            ) // TODO Review and test
        }

        /// This route is used by actors who would like to move their identity to another home server.
        /// This specific route is called by the "old" actor, notifying the server about their
        /// intent to move to another home server. To fulfill this action,
        /// a key trial must be passed for all keys with which the actor has sent messages with on this server.
        /// The "new" actor named in this request must confirm setting up this redirect.
        pub async fn set_up_redirect(
            &self,
            keytrials: &[KeyTrialResponse],
            fid: &FederationId,
        ) -> HttpResult<()> {
            let request = self
                .client
                .client
                .request(
                    SET_UP_REDIRECT.method,
                    self.instance_url.join(SET_UP_REDIRECT.path)?,
                )
                .bearer_auth(&self.token)
                .header(
                    "X-P2-core-keytrial",
                    urlencoding::encode(&json!(keytrials).to_string()).into_owned(),
                )
                .body(fid.to_string());

            let response = request.send().await?;
            matches_status_code(&[StatusCode::NO_CONTENT, StatusCode::OK], response.status())?;

            Ok(())
        }

        /// Stop an in-progress or existing redirection process from/to actor `fid`.
        pub async fn remove_redirect(&self, fid: &FederationId) -> HttpResult<()> {
            let request = P2RequestBuilder::new(&self)
                .homeserver(self.instance_url.clone())
                .endpoint(REMOVE_REDIRECT)
                .query("removeActorFid", &fid.to_string())
                .auth_token(self.token.clone())
                .build()
                .map_err(|e| RequestError::Custom {
                    reason: e.to_string(),
                })?;
            let response = self.send_request(request).await?;
            matches_status_code(&[StatusCode::OK, StatusCode::NO_CONTENT], response.status())
        }
    }
}

mod registration_not_required {
    use http::{HeaderValue, StatusCode};

    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use serde_json::{from_str, json};

    use crate::api::{P2RequestBuilder, SendsRequest, matches_status_code};
    use crate::types::keytrial::KeyTrialResponse;

    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
        /// Export all of your data for safekeeping or for importing it to another server.
        /// Only exports data for which a key trial has been passed.
        ///
        /// ## Returns
        ///
        /// ### `Ok()`
        ///
        /// - `None`, if the server has responded with `204`, indicating the server needs time to gather the
        ///   data. A Retry-After header is included in the response, indicating to the actor the point in
        ///   time at which they should query this endpoint again. If this point in time is after the expiry
        ///   timestamp of the completed key trial, another key trial needs to be performed to access the data.
        /// - `Some(Vec<u8>)` and the requested data, if the server could gather it in time.
        ///
        /// ### `Err()`
        ///
        /// Errors, if there is some error during building or sending the request, or with parsing the
        /// response.
        pub async fn export_all_data(
            &self,
            key_trials: &[KeyTrialResponse],
        ) -> HttpResult<Option<Vec<u8>>> {
            let request = P2RequestBuilder::new(&self)
                .auth_token(self.token.clone())
                .homeserver(self.instance_url.clone())
                .endpoint(EXPORT_DATA)
                .key_trials(key_trials.to_vec())
                .build()
                .map_err(RequestError::from)?;
            let response = self.send_request(request).await?;
            if response.status() == StatusCode::ACCEPTED {
                Ok(None)
            } else {
                let response_bytes = response.bytes().await?;
                Ok(Some(response_bytes.to_vec()))
            }
        }

        /// Delete all data associated with you from the server. Only deletes data associated with the keys for which the `KeyTrial` has been passed.
        ///
        /// ## Parameters
        ///
        /// - `break_redirect`: If a redirect has been set up previously: Whether to break that redirect with this action.
        pub async fn delete_data_from_server(
            &self,
            break_redirect: bool,
            keytrials: &[KeyTrialResponse],
        ) -> HttpResult<()> {
            let request = P2RequestBuilder::new(&self)
                .homeserver(self.instance_url.clone())
                .endpoint(DELETE_DATA)
                .auth_token(self.token.clone())
                .query("breakRedirect", &json!(break_redirect).to_string())
                .key_trials(keytrials.to_vec())
                .build()?;
            let response = self.send_request(request).await?;
            matches_status_code(
                &[StatusCode::OK, StatusCode::ACCEPTED, StatusCode::NO_CONTENT],
                response.status(),
            )
        }

        /// Fetch key trials and their responses from other actors. This route exists for
        /// transparency reasons, and allows actors in contact with the actor mentioned in `fid` to
        /// verify, that it was the actor who initiated setting up a redirect or the re-signing
        /// of messages—not a malicious home server.
        pub async fn get_actor_key_trial_responses(
            &self,
            fid: &FederationId,
            limit: u16,
            key_trial_id: Option<&str>,
            not_before: Option<u64>,
            not_after: Option<u64>,
        ) -> HttpResult<Vec<KeyTrialResponse>> {
            let mut request = P2RequestBuilder::new(&self)
                .auth_token(self.token.clone())
                .endpoint(GET_COMPLETED_KEYTRIALS_AND_RESPONSES)
                .replace_endpoint_substr(r#"{fid}"#, &fid.to_string())
                .query("limit", &limit.to_string());
            if let Some(id) = key_trial_id {
                request = request.query("id", id);
            }
            if let Some(nbf) = not_before {
                request = request.query("notBefore", &nbf.to_string());
            }
            if let Some(na) = not_after {
                request = request.query("notAfter", &na.to_string());
            }
            let request = request.build()?;

            let response = self.send_request(request).await?;
            matches_status_code(&[StatusCode::OK, StatusCode::NO_CONTENT], response.status())?;
            if response.status() == StatusCode::NO_CONTENT {
                return Ok(Vec::new());
            }
            match response.text().await {
                Ok(text) => from_str::<Vec<KeyTrialResponse>>(&text)
                    .map_err(RequestError::DeserializationError),
                Err(e) => Err(RequestError::Custom {
                    reason: format!("Could not get the full response text: {}", e),
                }),
            }
        }

        /// Fetch messages to be re-signed. Only returns messages where the signatures correlate
        /// to ID-Certs for which a key trial has been passed. If this endpoint is queried again
        /// while the previous batch of messages has not yet been re-signed (or only partially so),
        /// the returned message batch will contain those uncommitted messages again.
        ///
        /// ## Returns
        ///
        /// `(M, u64)`, where
        ///
        /// - `M: DeserializeOwned`: Message batch type, specified by the caller
        /// - `u64`: Value of response header "X-P2-Return-Body-Size-Limit", telling the client whether
        ///   the route to commit re-signed messages has an upload size limit, and what the size of
        ///   that limit is, in bytes. A value of 0 means that there is no limit.
        ///
        /// ## Errors
        ///
        /// This function may fail on errors encountered when building the request, when sending the
        /// request or when parsing the response. In particular, failure on response parsing is expected
        /// if
        ///
        /// - You receive a `403`/`404` error
        /// - The "X-P2-Return-Body-Size-Limit" header in the response is formatted incorrectly
        ///   (i.e. not a string-like unsigned-integer-like)
        /// - The "X-P2-Return-Body-Size-Limit" exists but is larger than `u64::MAX`
        pub async fn get_messages_to_be_resigned<M: DeserializeOwned>(
            &self,
            limit: u32,
            serial_number: Option<SerialNumber>,
        ) -> HttpResult<(M, u64)> {
            let mut request = P2RequestBuilder::new(&self)
                .auth_token(self.token.clone())
                .homeserver(self.instance_url.clone())
                .endpoint(GET_MESSAGES_TO_BE_RESIGNED)
                .query("limit", &limit.to_string());
            if let Some(serial) = serial_number {
                request = request.query("SerialNumber", &serial.to_string());
            }
            let request = request.build()?;
            let response = self.send_request(request).await?;
            let return_body_size_string = response
                .headers()
                .get("X-P2-Return-Body-Size-Limit")
                .unwrap_or(&HeaderValue::from_str("0").unwrap())
                .to_str()
                .map_err(|e| RequestError::Custom {
                    reason: e.to_string(),
                })?
                .to_string();
            let return_body_size =
                return_body_size_string
                    .parse::<u64>()
                    .map_err(|e| RequestError::Custom {
                        reason: e.to_string(),
                    })?;
            let response_text = response.text().await?;
            let m = from_str::<M>(&response_text)?;
            Ok((m, return_body_size))
        }

        /// Request allowing message re-signing. To fulfill this action, a key trial must be passed.
        /// Unlocks message re-signing for messages signed with keys for which a key trial has been passed.
        pub async fn request_message_resigning(
            &self,
            keytrials: &[KeyTrialResponse],
        ) -> HttpResult<()> {
            let request = P2RequestBuilder::new(&self)
                .homeserver(self.instance_url.clone())
                .endpoint(REQUEST_MESSAGE_RESIGNING)
                .key_trials(keytrials.to_vec())
                .auth_token(self.token.clone())
                .build()?;
            let response = self.send_request(request).await?;
            matches_status_code(&[StatusCode::OK, StatusCode::NO_CONTENT], response.status())
        }

        /// Stop an in-progress or existing re-signing process.
        pub async fn abort_message_resigning(&self, fid: &FederationId) -> HttpResult<()> {
            let request = P2RequestBuilder::new(&self)
                .homeserver(self.instance_url.clone())
                .endpoint(ABORT_MESSAGE_RESIGNING)
                .auth_token(self.token.clone())
                .query("removeActorFid", &fid.to_string())
                .build()?;
            let response = self.send_request(request).await?;
            matches_status_code(&[StatusCode::OK, StatusCode::NO_CONTENT], response.status())
        }

        /// Commit messages that have been re-signed to the server.
        pub async fn commit_resigned_messages<M: Serialize + DeserializeOwned>(
            &self,
            message_batch: M,
        ) -> HttpResult<Option<M>> {
            let request = P2RequestBuilder::new(&self)
                .auth_token(self.token.clone())
                .homeserver(self.instance_url.clone())
                .endpoint(COMMIT_RESIGNED_MESSAGES)
                .body(json!(message_batch))
                .build()?;
            let response = self.send_request(request).await?;
            matches_status_code(&[StatusCode::OK, StatusCode::NO_CONTENT], response.status())?;
            let response_text = response.text().await?;
            if response_text.trim() == "{}" || response_text.is_empty() {
                Ok(None)
            } else {
                match from_str::<M>(&response_text) {
                    Ok(next_message_batch) => Ok(Some(next_message_batch)),
                    Err(e) => Err(e.into()),
                }
            }
        }

        /// Tell the homeserver of the "old" actor account that you intend to set up a redirect to this actor
        /// ("this actor" refers to the actor this [Session] belongs to).
        pub async fn set_up_redirect_extern(&self, source: &FederationId) -> HttpResult<()> {
            let request = P2RequestBuilder::new(&self)
                .homeserver(self.instance_url.clone())
                .endpoint(SET_UP_REDIRECT_EXTERN)
                .auth_token(self.token.clone())
                .query("redirectSourceFid", &source.to_string())
                .build()?;
            let response = self.send_request(request).await?;
            matches_status_code(
                &[StatusCode::OK, StatusCode::NO_CONTENT, StatusCode::ACCEPTED],
                response.status(),
            )
        }

        /// Tell the homeserver of the "old" actor account that you no longer intend to set up a
        /// redirect to this actor ("this actor" refers to the actor this [Session] belongs to).
        pub async fn remove_redirect_extern(&self, source: &FederationId) -> HttpResult<()> {
            let request = P2RequestBuilder::new(&self)
                .homeserver(self.instance_url.clone())
                .endpoint(REMOVE_REDIRECT_EXTERN)
                .auth_token(self.token.clone())
                .query("redirectSourceFid", &source.to_string())
                .build()?;
            let response = self.send_request(request).await?;
            matches_status_code(&[StatusCode::OK, StatusCode::NO_CONTENT], response.status())
        }
    }
}
