// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;
use serde_json::from_str;

use crate::errors::RequestError;

pub mod core;

#[derive(Debug, Default, Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    headers: reqwest::header::HeaderMap,
}

pub type HttpResult<T> = Result<T, RequestError>;

impl HttpClient {
    pub fn new() -> Self {
        let client = reqwest::Client::new();
        let headers = reqwest::header::HeaderMap::new();
        Self { client, headers }
    }

    /// Creates a new instance of the client with the provided headers.
    pub fn with_headers(mut self, headers: reqwest::header::HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    /// Sends a request and returns the response.
    pub async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<String>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        // TODO: Parse url using url lib
        let mut request = self.client.request(method, url);
        request = request.headers(self.headers.clone());
        if let Some(body) = body {
            request = request.body(body);
        }
        request.send().await
    }

    /// Sends a request, handles the response, and returns the deserialized object.
    pub(crate) async fn handle_response<T: for<'a> Deserialize<'a>>(
        response: Result<reqwest::Response, reqwest::Error>,
    ) -> Result<T, RequestError> {
        let response = response?;
        let response_text = response.text().await?;
        let object = from_str::<T>(&response_text)?;
        Ok(object)
    }
}
