// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// The `core` module contains all API routes for implementing the core polyproto protocol in a client or server,
/// as well as some additional, useful types.
pub mod core;

/// Module containing code for cacheable ID-Certs.
#[cfg(feature = "types")]
pub mod cacheable_cert;

#[cfg(feature = "reqwest")]
pub use http_client::*;

#[cfg(feature = "reqwest")]
pub(crate) mod http_client {
    use std::fmt::Debug;
    use std::sync::Arc;

    use http::{Method, StatusCode};
    use reqwest::multipart::Form;
    use reqwest::{Client, Request, RequestBuilder, Response};
    use serde::Deserialize;
    use serde_json::{Value, from_str, json};
    use url::Url;

    use crate::certs::idcert::IdCert;
    use crate::errors::{InvalidInput, RequestError};
    use crate::key::PrivateKey;
    use crate::signature::Signature;
    use crate::types::keytrial::KeyTrialResponse;
    use crate::types::routes::Route;

    pub(crate) trait SendsRequest {
        async fn send_request(&self, request: Request) -> HttpResult<Response>;
        fn get_client(&self) -> Client;
    }

    impl SendsRequest for &HttpClient {
        async fn send_request(&self, request: Request) -> HttpResult<Response> {
            self.client
                .execute(request)
                .await
                .map_err(crate::errors::composite::RequestError::HttpError)
        }

        fn get_client(&self) -> Client {
            self.client.clone()
        }
    }

    impl<S: Signature, T: PrivateKey<S>> SendsRequest for &Session<S, T> {
        async fn send_request(&self, request: Request) -> HttpResult<Response> {
            self.get_client()
                .execute(request)
                .await
                .map_err(crate::errors::composite::RequestError::HttpError)
        }

        fn get_client(&self) -> Client {
            self.client.client.clone()
        }
    }

    pub(crate) struct P2RequestBuilder<'a, T: SendsRequest> {
        homeserver: Option<Url>,
        key_trials: Vec<KeyTrialResponse>,
        sensitive_solution: Option<String>,
        body: Option<Value>,
        auth_token: Option<String>,
        multipart: Option<Form>,
        endpoint: Route,
        replace_endpoint_substr: Vec<(String, String)>,
        query: Vec<(String, String)>,
        client: &'a T,
    }

    impl<'a, T: SendsRequest> P2RequestBuilder<'a, T> {
        /// Construct a new [P2RequestBuilder].
        pub(crate) fn new(client: &'a T) -> Self {
            Self {
                homeserver: None,
                client,
                endpoint: Route {
                    method: Method::default(),
                    path: "",
                },
                key_trials: Vec::new(),
                sensitive_solution: None,
                body: None,
                auth_token: None,
                multipart: None,
                query: Vec::new(),
                replace_endpoint_substr: Vec::new(),
            }
        }

        pub(crate) fn homeserver(mut self, url: Url) -> Self {
            self.homeserver = Some(url);
            self
        }

        /// Adds key trials to the response if none were added before. Replaces the currently stored
        /// vector of key trials with the one passed in this function, if one has been added before.
        pub(crate) fn key_trials(mut self, key_trials: Vec<KeyTrialResponse>) -> Self {
            self.key_trials = key_trials;
            self
        }

        /// Add a P2 sensitive solution if none was added before. Replaces the previously stored
        /// sensitive solution, if applicable.
        pub(crate) fn sensitive_solution(mut self, sensitive_solution: String) -> Self {
            self.sensitive_solution = Some(sensitive_solution);
            self
        }

        /// Add a request body to the request. Replaces the previously stored
        /// body, if applicable.
        ///
        /// ## Errors
        ///
        /// This function is infallible. However, building the request using `self.build()` will fail,
        /// if *both* a body and a multipart are present in the [P2RequestBuilder].
        pub(crate) fn body(mut self, body: Value) -> Self {
            self.body = Some(body); // once told me the world was gonna roll me
            self
        }

        /// Authorize using a Bearer token. The "Bearer " prefix will be added by `reqwest`. Replaces
        /// the previously stored token, if applicable.
        pub(crate) fn auth_token(mut self, token: String) -> Self {
            self.auth_token = Some(token);
            self
        }

        /// Add a multipart form to the request. Replaces the previously stored
        /// multipart, if applicable.
        ///
        /// ## Errors
        ///
        /// This function is infallible. However, building the request using `self.build()` will fail,
        /// if *both* a body and a multipart are present in the [P2RequestBuilder].
        pub(crate) fn multipart(mut self, form: Form) -> Self {
            self.multipart = Some(form);
            self
        }

        /// Set the endpoint of this request by supplying a [Route]. Replaces
        /// the previously selected route, if applicable.
        pub(crate) fn endpoint(mut self, route: Route) -> Self {
            self.endpoint = route;
            self
        }

        /// Add a substring replacement to this route. Multiple calls to this method will mean that
        /// multiple substring replacements will be performed. Replacements are done in FIFO order.
        ///
        /// Some [Route]s have path-query placeholders like `{rid}` or `{fid}`. If you are building
        /// a request to such a route, you will have to add a substring replacement using this method
        /// to send the request to the correct endpoint.
        ///
        /// ## Example
        ///
        /// ```rs
        /// let mut request_builder = Client::get_request_builder(method, url);
        /// request_builder.replace_endpoint_substr(r#"{rid}"#, "actual-resource-id");
        /// ```
        pub(crate) fn replace_endpoint_substr(mut self, from: &str, to: &str) -> Self {
            self.replace_endpoint_substr
                .push((from.to_string(), to.to_string()));
            self
        }

        /// Add a query parameter to this route. Does not replace previous query parameters.
        pub(crate) fn query(mut self, key: &str, value: &str) -> Self {
            self.query.push((key.to_string(), value.to_string()));
            self
        }

        /// Build the request. Fails, if both a body and a multipart are set, or if `reqwest` cannot
        /// build the request for any reason.
        pub(crate) fn build(self) -> Result<Request, InvalidInput> {
            if self.homeserver.is_none() {
                return Err(InvalidInput::Malformed(
                    "You forgot to set a homeserver URL".to_string(),
                ));
            }
            let mut path = self.endpoint.path.to_string();
            for (from, to) in self.replace_endpoint_substr.iter() {
                path = path.replace(from, to);
            }
            let url = self
                .homeserver
                .unwrap()
                .join(&path)
                .map_err(|e| InvalidInput::Malformed(e.to_string()))?;
            let mut request = self.client.get_client().request(self.endpoint.method, url);
            if let Some(token) = self.auth_token {
                request = request.bearer_auth(token);
            }
            if self.body.is_some() && self.multipart.is_some() {
                return Err(InvalidInput::Malformed(
                    "Cannot have both multipart and body in a request".to_string(),
                ));
            }
            if let Some(body) = self.body {
                request = request.body(body.to_string());
            } else if let Some(multipart) = self.multipart {
                request = request.multipart(multipart);
            }

            if !self.key_trials.is_empty() {
                request = request.header("X-P2-core-keytrial", json!(self.key_trials).to_string());
            }

            if let Some(sensitive_solution) = self.sensitive_solution {
                request = request.header("X-P2-sensitive-solution", sensitive_solution)
            }

            for (key, value) in self.query.iter() {
                request = request.query(&[(key, value)]);
            }

            request
                .build()
                .map_err(|e| InvalidInput::Malformed(e.to_string()))
        }
    }

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
            #[cfg(target_arch = "wasm32")]
            let client = reqwest::ClientBuilder::new()
                .user_agent(format!("polyproto-rs/{}", env!("CARGO_PKG_VERSION")))
                .build()?;
            #[cfg(not(target_arch = "wasm32"))]
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
        #[cfg(not(target_arch = "wasm32"))] // WASM doesn't support zstd, so this function can just be left out
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

        /// Boilerplate reducing request builder when using [Route]s to make basic requests.
        pub(crate) fn request_route(
            &self,
            instance_url: &Url,
            route: Route,
        ) -> Result<RequestBuilder, url::ParseError> {
            Ok(self
                .client
                .request(route.method, instance_url.join(route.path)?))
        }

        /// Sends an HTTP request to the specified URL using the given method and optional body.
        ///
        /// ## Errors
        ///
        /// This function will return an error in the following cases:
        /// * The URL is invalid and cannot be parsed.
        /// * There are issues sending the request using the underlying reqwest client.
        /// * The request fails due to network problems or other errors encountered during execution.
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

        /// Sends an HTTP request to the specified URL using the given method and optional body, and attempts
        /// to deserialize the response into a specified type.
        ///
        /// ## Returns
        ///
        /// Returns an `HttpResult<T>` containing the deserialized response of type `T` if successful.
        ///
        /// ## Errors
        ///
        /// This function will return an error in the following cases:
        /// * The URL is invalid and cannot be parsed.
        /// * There are issues sending the request using the underlying reqwest client.
        /// * The request fails due to network problems or other errors encountered during execution.
        /// * The response body cannot be deserialized into the specified type `T`. This might happen,
        ///   if the server responds with no body or an empty string to indicate an empty container,
        ///   like `None` when `T = Option<...>`, an empty vector if `T = Vec<...>` and so on. If such
        ///   behaviour is expected, use `request` instead and "manually" deserialize the result into
        ///   the desired type.
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

    /// Returns `Ok(())` if `expected` contains `actual`, or an appropriate `RequestError::StatusCode`
    /// otherwise.
    pub(crate) fn matches_status_code(
        expected: &[StatusCode],
        actual: StatusCode,
    ) -> HttpResult<()> {
        if expected.contains(&actual) {
            Ok(())
        } else {
            Err(RequestError::StatusCode {
                received: actual,
                expected: expected.into(),
            })
        }
    }

    // i would like to move all routes requiring auth to the Session struct. all other routes can stay
    // at HttpClient.

    #[derive(Debug, Clone)]
    /// An authenticated polyproto session on an instance. Can optionally store the corresponding [IdCert]
    /// and [PrivateKey] for easy access to APIs requiring these parameters. Also gives access to
    /// unauthenticated APIs by exposing the inner [HttpClient].
    pub struct Session<S: Signature, T: PrivateKey<S>> {
        /// The authentication token of this session.
        pub token: String,
        /// A reference to the underlying [HttpClient].
        pub client: Arc<HttpClient>,
        /// The URL of the instance this session belongs to.
        pub instance_url: Url,
        pub(crate) certificate: Option<IdCert<S, T::PublicKey>>,
        pub(crate) signing_key: Option<T>,
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

        /// Re-set the token, in case it changes.
        pub fn set_token(&mut self, token: &str) {
            self.token = token.to_string();
        }

        /// Add or update the [IdCert] and [PrivateKey] stored by the [Session], used for authenticated
        /// operations requiring signing.
        pub fn set_cert_and_key(&mut self, cert: IdCert<S, T::PublicKey>, signing_key: T) {
            self.certificate = Some(cert);
            self.signing_key = Some(signing_key);
        }
    }
}
