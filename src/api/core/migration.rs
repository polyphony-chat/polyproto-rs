// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use super::*;
mod registration_required {
    use http::StatusCode;
    use reqwest::multipart::Form;
    use serde_json::json;

    use crate::api::{P2RequestBuilder, SendsRequest, matches_status_code};
    use crate::types::P2Export;
    use crate::types::keytrial::KeyTrialResponse;

    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
        /// Import a `P2Export` file. `messages` in this file must have been re-signed to the current actor.
        /// Only messages classified as
        /// ["Information not tied to a specific context"](https://docs.polyphony.chat/Protocol%20Specifications/core/#:~:text=Example%3A%20Information%20not,without%0Aany%20issues.)
        /// can be imported.
        pub async fn import_data_to_server(
            &self,
            sensitive_solution: &str,
            data: P2Export,
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
    use crate::types::keytrial::KeyTrialResponse;

    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
        pub async fn export_all_data() -> HttpResult<Vec<u8>> {
            todo!()
        }

        pub async fn delete_data_from_server() -> HttpResult<()> {
            todo!()
        }

        pub async fn get_actor_key_trial_responses() -> HttpResult<Vec<KeyTrialResponse>> {
            todo!()
        }

        pub async fn get_messages_to_be_resigned<M>() -> HttpResult<M> {
            todo!()
        }

        pub async fn request_message_resigning() -> HttpResult<()> {
            todo!()
        }

        pub async fn abort_message_resigning() -> HttpResult<()> {
            todo!()
        }

        pub async fn commit_resigned_messages<M>() -> HttpResult<Option<M>> {
            todo!()
        }

        pub async fn set_up_redirect_extern() -> HttpResult<()> {
            todo!()
        }

        pub async fn remove_redirect_extern() -> HttpResult<()> {
            todo!()
        }
    }

    impl HttpClient {}
}
