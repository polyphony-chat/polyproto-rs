// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;
use serde_json::from_str;

pub mod authentication;
pub mod events;
pub mod identity;

#[derive(Debug, Default, Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    headers: reqwest::header::HeaderMap,
}

impl HttpClient {
    pub fn new() -> Self {
        let client = reqwest::Client::new();
        let headers = reqwest::header::HeaderMap::new();
        Self { client, headers }
    }

    pub fn with_headers(mut self, headers: reqwest::header::HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    pub async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<String>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut request = self.client.request(method, url);
        request = request.headers(self.headers.clone());
        if let Some(body) = body {
            request = request.body(body);
        }
        request.send().await
    }

    /// Sends a [`ChorusRequest`] and returns a [`ChorusResult`] that contains a [`T`] if the request
    /// was successful, or a [`ChorusError`] if the request failed.
    pub(crate) async fn handle_response<T: for<'a> Deserialize<'a>>(
        response: Result<reqwest::Response, reqwest::Error>,
    ) -> Result<T, crate::errors::composite::InvalidCert> {
        let response = match response {
            Ok(response) => response,
            Err(e) => return todo!(),
        };
        let response_text = match response.text().await {
            Ok(string) => string,
            Err(e) => return todo!(),
        };
        let object = match from_str::<T>(&response_text) {
            Ok(object) => object,
            Err(e) => return todo!(),
        };
        Ok(object)
    }
}
