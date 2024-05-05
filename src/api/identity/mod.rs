// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use reqwest::Method;

use crate::certs::idcert::IdCert;
use crate::key::PublicKey;
use crate::signature::Signature;
use crate::types::entities::Challenge;

use super::{HttpClient, HttpResult};

impl HttpClient {
    /// Request a challenge string.
    ///
    /// **GET** *{base_url}*/.p2/core/v1/challenge
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

    /// Rotate the server's identity key. Returns the new server [IdCert].
    ///
    /// **PUT** *{base_url}*/.p2/core/v1/key/server
    /// - Requires authentication
    /// - Requires server administrator privileges
    pub async fn rotate_server_identity_key<S: Signature, P: PublicKey<S>>(
        &self,
        base_url: &str,
    ) -> HttpResult<IdCert<S, P>> {
        let response = self
            .request(
                Method::PUT,
                &format!("{}/.p2/core/v1/key/server", base_url),
                None,
            )
            .await?;

        Ok(IdCert::from_pem(response.text().await?.as_str())?)
    }
}
