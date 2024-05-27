// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;
use serde_json::from_str;
use url::Url;

use crate::errors::RequestError;

pub mod core;

#[derive(Debug, Clone)]
/// A client for making HTTP requests to a polyproto home server.
///
/// # Example
///
/// ```rs
/// let mut header_map = reqwest::header::HeaderMap::new();
/// header_map.insert("Authorization", "nx8r902hjkxlo2n8n72x0");
/// let client = HttpClient::new("https://example.com").unwrap();
/// client.headers(header_map);
///
/// let challenge: ChallengeString = client.get_challenge_string().await.unwrap();
/// ```
pub struct HttpClient {
    client: reqwest::Client,
    headers: reqwest::header::HeaderMap,
    pub(crate) url: Url,
}

pub type HttpResult<T> = Result<T, RequestError>;

impl HttpClient {
    /// Creates a new instance of the client with no further configuration. A client initialized
    /// with this method can not be used for any requests that require authentication.
    ///
    /// # Arguments
    ///
    /// * `url` - The base URL of a polyproto home server.
    pub fn new(url: &str) -> HttpResult<Self> {
        let client = reqwest::Client::new();
        let headers = reqwest::header::HeaderMap::new();
        let url = Url::parse(url)?;

        Ok(Self {
            client,
            headers,
            url,
        })
    }

    /// Sets the headers for the client.
    pub fn headers(&mut self, headers: reqwest::header::HeaderMap) {
        self.headers = headers;
    }

    /// Returns the URL
    pub fn url(&self) -> String {
        self.url.to_string()
    }

    /// Sets the base URL of the client.
    pub fn set_url(&mut self, url: &str) -> HttpResult<()> {
        self.url = Url::parse(url)?;
        Ok(())
    }

    /// Sends a request and returns the response.
    pub async fn request<T: Into<reqwest::Body>>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<T>,
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
