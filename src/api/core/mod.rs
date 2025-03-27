// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::UNIX_EPOCH;

use crate::certs::idcerttbs::IdCertTbs;
use crate::url::Url;

use crate::key::PublicKey;
use crate::signature::Signature;

use super::cacheable_cert::CacheableIdCert;
use crate::types::x509_cert::SerialNumber;
use log::trace;

use crate::certs::SessionId;
use crate::certs::idcert::IdCert;
#[cfg(feature = "reqwest")]
use crate::errors::RequestError;
use crate::key::PrivateKey;
use crate::types::routes::core::v1::*;
use crate::types::{EncryptedPkm, FederationId, Service, ServiceName};

#[cfg(feature = "reqwest")]
use super::{HttpClient, HttpResult, Session};

#[cfg(feature = "reqwest")]
mod federated_identity;
#[cfg(feature = "reqwest")]
mod migration;
#[cfg(feature = "reqwest")]
mod rawr;
#[cfg(feature = "reqwest")]
mod services;

#[cfg(feature = "reqwest")]
pub use routes::*;

/// Get the current UNIX timestamp according to the system clock.
pub fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Response from querying a polyproto `.well-known` endpoint.
pub struct WellKnown {
    api: Url,
}

impl WellKnown {
    /// Return the [Url] that this .well-known entry points to.
    pub fn api(&self) -> &Url {
        &self.api
    }

    /// Create [Self] from a [Url], setting the `api` field to the supplied URL without performing any
    /// validity checks. Use [Self::new()] if you want to create [Self] from a link to a "visible domain".
    pub fn from_url(url: &Url) -> Self {
        Self::from(url.clone())
    }

    /**
    Checks whether the "visible domain" in a certificate matches the "actual url" specified by the
    `.well-known` endpoint of that "visible domain".

    ## .well-known validation criterions

    > *The following is an excerpt from section 3.1 of the polyproto specification.*

    polyproto servers can be hosted under a domain name different from the domain name appearing on ID-Certs managed by that server if all the following conditions are met:
    1. Define the "visible domain name" as the domain name visible on an ID-Cert.
    2. Define the "actual domain name" as the domain name where the polyproto server is actually hosted under.
    3. The visible domain name must have a URI [visible domain name]/.well-known/polyproto-core, accessible via an HTTP GET request.
    4. The resource accessible at this URI must be a JSON object formatted as such:

    ```json
     {
         "api": "[actual domain name]/.p2/core/"
     }
    ```

    5.  The ID-Cert received when querying [actual domain name]/.p2/core/idcert/server with an HTTP
        GET request must have a field "issuer" containing domain components (dc) that, when parsed,
        equal the domain name of the visible domain name. If the domain components in this field do
        not match the domain components of the visible domain name, the server hosted under the actual
        domain name must not be treated as a polyproto server for the visible domain name.

    If all the above-mentioned conditions can be fulfilled, the client
    can treat the server located at the actual domain name as a polyproto server serving the visible domain
    name. Clients must not treat the server located at the actual domain name as a polyproto server
    serving the actual domain name.

    ## TL;DR

    This function verifies these 5 criteria. If all of these criteria
    are fulfilled, `true` is returned. If any of the criteria are not fulfilled, `false` is returned.
    Criterion #3 is fulfilled by the existence of this struct object.
    */
    // TODO: Test me
    pub fn matches_certificate<S: Signature, P: PublicKey<S>>(
        &self,
        cert: &IdCertTbs<S, P>,
    ) -> bool {
        let visible_domain = match cert.issuer_url() {
            Ok(url) => url,
            Err(_) => return false,
        };
        let actual_domain = &self.api.host();
        trace!(
            "Checking for equality of {:?} and {:?}",
            visible_domain.host(),
            *actual_domain
        );
        visible_domain.host() == *actual_domain
    }

    /// Request the contents of the polyproto `.well-known` endpoint from a base url.
    ///
    /// This is a shorthand for
    /// ```rs
    /// self.request_as::<WellKnown>(http::Method::GET, url, None).await
    /// ```
    ///
    /// ## Errors
    ///
    /// This method will error if the server is unreachable or if the resource is malformed.
    #[cfg(feature = "reqwest")]
    pub async fn new(client: &HttpClient, url: &Url) -> HttpResult<Self> {
        client.get_well_known(url).await
    }
}

impl std::fmt::Display for WellKnown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.api.as_str())
    }
}

impl From<Url> for WellKnown {
    /// Does NOT check whether [Self] is valid. Use [Self::new()] instead.
    fn from(value: Url) -> Self {
        WellKnown { api: value }
    }
}

impl<'a> From<&'a WellKnown> for &'a str {
    fn from(value: &'a WellKnown) -> Self {
        value.api.as_str()
    }
}

impl From<WellKnown> for Url {
    fn from(value: WellKnown) -> Self {
        value.api
    }
}

impl From<WellKnown> for String {
    fn from(value: WellKnown) -> Self {
        value.api.to_string()
    }
}

#[cfg(feature = "reqwest")]
/// Module containing an implementation of a reqwest-based HTTP client with polyproto routes
/// implemented on it.
pub mod routes {
    use serde::{Deserialize, Serialize};
    use url::Url;

    use crate::api::{HttpClient, HttpResult};
    use crate::types::Service;

    use super::WellKnown;

    // Core Routes: No registration needed
    impl HttpClient {
        /// Request the contents of the polyproto `.well-known` endpoint from a base url.
        ///
        /// This is a shorthand for
        /// ```rs
        /// self.request_as::<WellKnown>(http::Method::GET, url, None).await
        /// ```
        ///
        /// ## Errors
        ///
        /// This method will error if the server is unreachable or if the resource is malformed.
        pub async fn get_well_known(&self, url: &Url) -> HttpResult<WellKnown> {
            let url = url.join(".well-known/polyproto-core")?;
            self.request_as(http::Method::GET, url.as_str(), None).await
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
    /// Represents a pair of an [IdCert] and a token, used in the API as a response when an [IdCsr] has
    /// been accepted by the server.
    pub struct IdCertToken {
        /// The [IdCert] as a PEM encoded string
        pub id_cert: String,
        /// The token as a string
        pub token: String,
    }

    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[derive(Debug, Clone, PartialEq, Eq)]
    /// Represents a response to a service discovery deletion request. Contains the deleted service
    /// and, if applicable, the new primary service provider for the service.
    pub struct ServiceDeleteResponse {
        /// The service that was deleted.
        pub deleted: Service,
        /// The new primary service provider for the service, if applicable.
        pub new_primary: Option<Service>,
    }
}
