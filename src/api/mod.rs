// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;
use serde_json::from_str;
use url::Url;

use crate::errors::RequestError;

/// The `core` module contains all API routes for implementing the core polyproto protocol in a client or server.
pub mod core;

#[derive(Debug, Clone)]
/// A client for making HTTP requests to a polyproto home server. Stores headers such as the
/// authentication token, and the base URL of the server. Both the headers and the URL can be
/// modified after the client is created. However, the intended use case is to create one client
/// per actor, and use it for all requests made by that actor.
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
    /// The reqwest client used to make requests.
    pub client: reqwest::Client,
    headers: reqwest::header::HeaderMap,
    version: http::Version, //TODO: Allow setting HTTP version?
    pub(crate) url: Url,
    zstd_compression: bool,
}

/// A type alias for the result of an HTTP request.
pub type HttpResult<T> = Result<T, RequestError>;

impl HttpClient {
    /// Creates a new instance of the client with no further configuration. To access routes which
    /// require authentication, you must set the authentication header using the `headers` method.
    ///
    /// # Arguments
    ///
    /// * `url` - The base URL of a polyproto home server.
    ///
    /// # Errors
    ///
    /// Will fail if the URL is invalid or if there are issues creating the reqwest client.
    pub fn new(url: &str) -> HttpResult<Self> {
        let client = reqwest::ClientBuilder::new()
            .zstd(true)
            .user_agent(format!("polyproto-rs/{}", env!("CARGO_PKG_VERSION")))
            .build()?;
        let headers = reqwest::header::HeaderMap::new();
        let url = Url::parse(url)?;
        let version = http::Version::HTTP_11;

        Ok(Self {
            client,
            headers,
            url,
            version,
            zstd_compression: true,
        })
    }

    /// Creates a new instance of the client with the specified arguments. To access routes which
    /// require authentication, you must set an authentication header.
    ///
    /// # Arguments
    ///
    /// * `url` - The base URL of a polyproto home server.
    /// * `headers`: [reqwest::header::HeaderMap]
    /// * `version`: Version of the HTTP spec
    /// * `zstd_compression`: Whether to use zstd compression for responses.
    ///
    /// # Errors
    ///
    /// Will fail if the URL is invalid or if there are issues creating the reqwest client.
    pub fn new_with_args(
        url: &str,
        headers: reqwest::header::HeaderMap,
        version: http::Version,
        zstd_compression: bool,
    ) -> HttpResult<Self> {
        let client = reqwest::ClientBuilder::new()
            .zstd(zstd_compression)
            .user_agent(format!("polyproto-rs/{}", env!("CARGO_PKG_VERSION")))
            .build()?;
        let url = Url::parse(url)?;
        Ok(Self {
            client,
            headers,
            version,
            url,
            zstd_compression,
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
    ) -> HttpResult<reqwest::Response> {
        Url::parse(url)?;
        let mut request = self.client.request(method, url);
        request = request.headers(self.headers.clone());
        if let Some(body) = body {
            request = request.body(body);
        }
        Ok(request.send().await?)
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
