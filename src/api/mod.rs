// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::from_str;
use url::Url;

use crate::certs::idcert::IdCert;
use crate::errors::RequestError;
use crate::key::PrivateKey;
use crate::signature::Signature;

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
    pub fn new() -> HttpResult<Self> {
        let client = reqwest::ClientBuilder::new()
            .zstd(true)
            .user_agent(format!("polyproto-rs/{}", env!("CARGO_PKG_VERSION")))
            .build()?;
        let headers = reqwest::header::HeaderMap::new();

        Ok(Self { client, headers })
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
        headers: reqwest::header::HeaderMap,
        zstd_compression: bool,
    ) -> HttpResult<Self> {
        let client = reqwest::ClientBuilder::new()
            .zstd(zstd_compression)
            .user_agent(format!("polyproto-rs/{}", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { client, headers })
    }

    /// Sets the headers for the client.
    pub fn headers(&mut self, headers: reqwest::header::HeaderMap) {
        self.headers = headers;
    }

    /// Sends a request and returns a [HttpResult].
    /// DOCUMENTME
    pub async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<reqwest::Body>,
    ) -> HttpResult<reqwest::Response> {
        Url::parse(url)?;
        let mut request = self.client.request(method, url);
        request = request.headers(self.headers.clone());
        if let Some(body) = body {
            request = request.body(body);
        }
        Ok(request.send().await?)
    }

    /// DOCUMENTME
    pub async fn request_as<T: for<'a> Deserialize<'a>>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<reqwest::Body>,
    ) -> HttpResult<T> {
        let url = Url::parse(url)?;
        let mut request = self.client.request(method, url);
        request = request.headers(self.headers.clone());
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request.send().await;
        Self::handle_response(response).await
    }

    /// Sends a request, handles the response, and returns the deserialized object.
    pub(crate) async fn handle_response<T: for<'a> Deserialize<'a>>(
        response: Result<reqwest::Response, reqwest::Error>,
    ) -> HttpResult<T> {
        let response = response?;
        let response_text = response.text().await?;
        let object = from_str::<T>(&response_text)?;
        Ok(object)
    }
}

// i would like to move all routes requiring auth to the Session struct. all other routes can stay
// at HttpClient.

#[derive(Debug, Clone)]
/// An authenticated polyproto session on an instance. Can optionally store the corresponding [IdCert]
/// and [PrivateKey] for easy access to APIs requiring these parameters. Also gives access to
/// unauthenticated APIs by exposing the inner [HttpClient].
pub struct Session<S: Signature, T: PrivateKey<S>> {
    token: String,
    pub client: Arc<HttpClient>,
    pub instance_url: Url,
    certificate: Option<IdCert<S, T::PublicKey>>,
    signing_key: Option<T>,
}

impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
    /// Creates a new authenticated `Session` instance.
    ///
    /// # Parameters
    /// - `client`: A reference to the [`HttpClient`] used for making API requests.
    /// - `token`: A string slice representing the authentication token.
    /// - `instance_url`: The [`Url`] of the instance to which the session connects.
    /// - `cert_and_key`: An optional tuple containing an [`IdCert`] and a corresponding private key.
    ///   If provided, these values will be used for authenticated operations requiring signing.
    ///
    /// # Returns
    /// A new `Session` instance initialized with the provided parameters.
    ///
    /// # Example
    /// ```rust
    /// use std::sync::Arc;
    /// use some_crate::{Session, HttpClient, IdCert, Url};
    ///
    /// let client = HttpClient::new();
    /// let token = "some_auth_token";
    /// let instance_url = Url::parse("https://example.com").unwrap();
    /// let cert_and_key = None; // or Some((id_cert, private_key));
    ///
    /// let session = Session::new(&client, token, instance_url, cert_and_key);
    /// ```
    ///
    /// The returned `Session` provides access to authenticated and unauthenticated APIs,
    /// and stores optional credentials for signing requests when required.
    pub fn new(
        client: &HttpClient,
        token: &str,
        instance_url: Url,
        cert_and_key: Option<(IdCert<S, T::PublicKey>, T)>,
    ) -> Self {
        let (certificate, signing_key) = match cert_and_key {
            Some((c, s)) => (Some(c), Some(s)),
            None => (None, None),
        };
        Self {
            token: token.to_string(),
            client: Arc::new(client.clone()),
            instance_url,
            certificate,
            signing_key,
        }
    }
}
