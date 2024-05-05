// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use reqwest::Method;

use crate::types::entities::Challenge;

use super::{HttpClient, HttpResult};

impl HttpClient {
    pub async fn get_challenge(&self, base_url: &str) -> HttpResult<Challenge> {
        let response = self
            .request(
                Method::GET,
                &format!("{}/.p2/core/v1/challenge", base_url),
                None,
            )
            .await;

        Self::handle_response(response).await
    }
}
