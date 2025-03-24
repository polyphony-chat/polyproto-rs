// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use super::*;
mod registration_required {
    use http::StatusCode;
    use reqwest::multipart::Form;

    use crate::api::matches_status_code;
    use crate::types::P2Export;

    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
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

        pub async fn set_up_redirect() -> HttpResult<()> {
            todo!()
        }

        pub async fn remove_redirect() -> HttpResult<()> {
            todo!()
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
