// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::UNIX_EPOCH;

use crate::certs::idcerttbs::IdCertTbs;
use crate::types::x509_cert::SerialNumber;
use crate::url::Url;
use cacheable_cert::CacheableIdCert;
use log::trace;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::certs::idcert::IdCert;
use crate::certs::SessionId;
use crate::errors::RequestError;
use crate::key::{PrivateKey, PublicKey};
use crate::signature::Signature;
use crate::types::routes::core::v1::*;
use crate::types::{EncryptedPkm, FederationId, Service, ServiceName};

use super::{HttpClient, HttpResult, Session};

/// Module containing code for cacheable ID-Certs.
pub mod cacheable_cert;

/// Get the current UNIX timestamp according to the system clock.
pub fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
    /// Request the server to rotate its identity key and return the new [IdCert]. This route is
    /// only available to server administrators.
    ///
    /// ## Safety guarantees
    ///
    /// The resulting [IdCert] is verified and has the same safety guarantees as specified under
    /// [IdCert::full_verify_home_server()], as this method calls that method internally.
    pub async fn rotate_server_identity_key(&self) -> HttpResult<IdCert<S, T::PublicKey>> {
        let request_url = self.instance_url.join(ROTATE_SERVER_IDENTITY_KEY.path)?;
        let request_response = self
            .client
            .client
            .request(ROTATE_SERVER_IDENTITY_KEY.method.clone(), request_url)
            .bearer_auth(&self.token)
            .send()
            .await;
        let pem = HttpClient::handle_response::<String>(request_response).await?;
        log::debug!("Received IdCert: \n{}", pem);
        let id_cert = IdCert::<S, T::PublicKey>::from_pem_unchecked(&pem)?;
        match id_cert.full_verify_home_server(
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ) {
            Ok(_) => (),
            Err(e) => return Err(RequestError::ConversionError(e.into())),
        };
        Ok(id_cert)
    }

    /// Inform a foreign server about a new [IdCert] for a session.
    pub async fn update_session_id_cert(
        &self,
        new_cert: IdCert<S, T::PublicKey>,
    ) -> HttpResult<()> {
        let request_url = self.instance_url.join(UPDATE_SESSION_IDCERT.path)?;
        self.client
            .client
            .request(UPDATE_SESSION_IDCERT.method.clone(), request_url)
            .bearer_auth(&self.token)
            .body(new_cert.to_pem(der::pem::LineEnding::LF)?)
            .send()
            .await?;
        Ok(())
    }

    /// Tell a server to delete a session, revoking the session token.
    pub async fn delete_session(&self, session_id: &SessionId) -> HttpResult<()> {
        let request_url = self.instance_url.join(DELETE_SESSION.path)?;
        let body = json!({ "session_id": session_id.to_string() });
        self.client
            .client
            .request(DELETE_SESSION.method.clone(), request_url)
            .bearer_auth(&self.token)
            .body(body.to_string())
            .send()
            .await?;
        Ok(())
    }

    /// Upload encrypted private key material to the server for later retrieval. The upload size
    /// must not exceed the server's maximum upload size for this route. This is usually not more
    /// than 10kb and can be as low as 800 bytes, depending on the server configuration.
    ///
    /// The `data` parameter is a vector of [EncryptedPkm] which contains the serial number of the
    /// ID-Cert and the encrypted private key material. Naturally, the server cannot check the
    /// contents of the encrypted private key material. However, it is recommended to store the data
    /// in a `SubjectPublicKeyInfo` structure, where the public key is the private key material.
    pub async fn upload_encrypted_pkm(&self, data: Vec<EncryptedPkm>) -> HttpResult<()> {
        let mut body = Vec::new();
        for pkm in data.iter() {
            body.push(json!(pkm));
        }
        let request_url = self.instance_url.join(UPLOAD_ENCRYPTED_PKM.path)?;
        self.client
            .client
            .request(UPLOAD_ENCRYPTED_PKM.method.clone(), request_url)
            .bearer_auth(&self.token)
            .body(json!(body).to_string())
            .send()
            .await?;
        Ok(())
    }

    /// Retrieve encrypted private key material from the server. The serial_numbers, if provided,
    /// must match the serial numbers of ID-Certs that the client has uploaded key material for.
    /// If no serial_numbers are provided, the server will return all key material that the client
    /// has uploaded.
    pub async fn get_encrypted_pkm(
        &self,
        serials: Vec<SerialNumber>,
    ) -> HttpResult<Vec<EncryptedPkm>> {
        let request_url = self.instance_url.join(GET_ENCRYPTED_PKM.path)?;
        let mut body = Vec::new();
        for serial in serials.iter() {
            body.push(json!(serial.try_as_u128()?));
        }
        let request = self
            .client
            .client
            .request(GET_ENCRYPTED_PKM.method.clone(), request_url)
            .bearer_auth(&self.token)
            .body(json!(body).to_string());
        let response =
            HttpClient::handle_response::<Vec<EncryptedPkm>>(request.send().await).await?;
        let mut vec_pkm = Vec::new();
        for pkm in response.into_iter() {
            vec_pkm.push(pkm);
        }
        Ok(vec_pkm)
    }

    /// Delete encrypted private key material from the server. The serials must match the
    /// serial numbers of ID-Certs that the client has uploaded key material for.
    pub async fn delete_encrypted_pkm(&self, serials: Vec<SerialNumber>) -> HttpResult<()> {
        let request_url = self.instance_url.join(DELETE_ENCRYPTED_PKM.path)?;
        let mut body = Vec::new();
        for serial in serials.iter() {
            body.push(json!(serial.try_as_u128()?));
        }
        self.client
            .client
            .request(DELETE_ENCRYPTED_PKM.method.clone(), request_url)
            .bearer_auth(&self.token)
            .body(json!(body).to_string())
            .send()
            .await?;
        Ok(())
    }

    /// Add a service to the list of discoverable services. The service must be a valid [Service].
    /// If the service provider is the first to provide this service, or if the [Service] has a
    /// property of `primary` set to `true`, the service will be marked as the primary service
    /// provider for this service.
    ///
    /// The server will return a [Vec] of all [Service]s affected
    /// by this operation. This [Vec] will have a length of 1, if no other service entry was
    /// affected, and a length of 2 if this new service entry has replaced an existing one in the
    /// role of primary service provider.
    pub async fn add_discoverable_service(&self, service: &Service) -> HttpResult<Vec<Service>> {
        let request = self
            .client
            .client
            .request(
                CREATE_DISCOVERABLE.method.clone(),
                self.instance_url.join(CREATE_DISCOVERABLE.path)?,
            )
            .bearer_auth(&self.token)
            .body(json!(service).to_string());
        let response = request.send().await;
        HttpClient::handle_response::<Vec<Service>>(response).await
    }

    /// Delete a discoverable service from the list of discoverable services. The service must be a
    /// valid [Service] that exists in the list of discoverable services. On success, the server will
    /// return a [ServiceDeleteResponse] containing the deleted service and, if applicable, the new
    /// primary service provider for the service.
    pub async fn delete_discoverable_service(
        &self,
        url: &Url,
        name: &ServiceName,
    ) -> HttpResult<ServiceDeleteResponse> {
        let request = self
            .client
            .client
            .request(
                DELETE_DISCOVERABLE.method.clone(),
                self.instance_url.join(DELETE_DISCOVERABLE.path)?,
            )
            .bearer_auth(&self.token)
            .body(
                json!({
                    "url": url,
                    "name": name,
                })
                .to_string(),
            );
        let response = request.send().await;
        HttpClient::handle_response::<ServiceDeleteResponse>(response).await
    }

    /// Set the primary service provider for a service, by specifying the URL of the new primary
    /// service provider and the name of the service. The server will return a [Vec] of all [Service]s
    /// affected by this operation. This [Vec] will have a length of 1, if no other service entry was
    /// affected, and a length of 2 if this new service entry has replaced an existing one in the
    /// role of primary service provider.
    pub async fn set_primary_service_provider(
        &self,
        url: &Url,
        name: &ServiceName,
    ) -> HttpResult<Vec<Service>> {
        let request = self
            .client
            .client
            .request(
                SET_PRIMARY_DISCOVERABLE.method.clone(),
                self.instance_url.join(SET_PRIMARY_DISCOVERABLE.path)?,
            )
            .bearer_auth(&self.token)
            .body(
                json!({
                    "url": url,
                    "name": name
                })
                .to_string(),
            );
        let response = request.send().await;
        HttpClient::handle_response::<Vec<Service>>(response).await
    }
}

// Core Routes: No registration needed
impl HttpClient {
    /// Request the server's public [IdCert]. Specify a unix timestamp to get the IdCert which was
    /// valid at that time. If no timestamp is provided, the current IdCert is returned.
    ///
    /// ## Safety guarantees
    ///
    /// The resulting [CacheableIdCert] has not been verified. After converting it into an [IdCert],
    /// you should verify it – if the conversion has not done this already.
    /// [IdCert::full_verify_home_server()], as this method calls that method internally.
    pub async fn get_server_id_cert(
        &self,
        unix_time: Option<u64>,
        instance_url: &Url,
    ) -> HttpResult<CacheableIdCert> {
        let request_url = instance_url.join(GET_SERVER_IDCERT.path)?;
        let mut request = self
            .client
            .request(GET_SERVER_IDCERT.method.clone(), request_url);
        if let Some(time) = unix_time {
            request = request.body(json!({ "timestamp": time }).to_string());
        }
        let response = request.send().await;
        trace!("Got response: {:?}", response);
        let id_cert = HttpClient::handle_response::<CacheableIdCert>(response).await?;
        Ok(id_cert)
    }

    /// Request the [IdCert]s of an actor. Specify the federation ID of the actor to get the IdCerts
    /// of that actor. Returns a vector of IdCerts which were valid for the actor at the specified
    /// time. If no timestamp is provided, the current IdCerts are returned.
    ///
    /// ## Safety guarantees
    ///
    /// The resulting [CacheableIdCert]s are not verified. The caller is responsible for verifying the correctness
    /// of these `IdCert`s by converting verifying them using [IdCert::full_verify_actor()] before use.
    pub async fn get_actor_id_certs(
        &self,
        fid: &str,
        unix_time: Option<u64>,
        session_id: Option<&SessionId>,
        instance_url: &Url,
    ) -> HttpResult<Vec<CacheableIdCert>> {
        let request_url = instance_url.join(&format!("{}{}", GET_ACTOR_IDCERTS.path, fid))?;
        let mut request = self
            .client
            .request(GET_ACTOR_IDCERTS.method.clone(), request_url);
        let body = match (unix_time, session_id) {
            // PRETTYFYME
            (Some(time), Some(session)) => {
                Some(json!({ "timestamp": time, "session_id": session.to_string() }))
            }
            (Some(time), None) => Some(json!({"timestamp": time})),
            (None, Some(session)) => Some(json!({"session_id": session.to_string()})),
            (None, None) => None,
        };
        if let Some(body) = body {
            request = request.body(body.to_string());
        }
        let response = request.send().await;
        let pems = HttpClient::handle_response::<Vec<CacheableIdCert>>(response).await?;
        let mut vec_idcert = Vec::new();
        for cert in pems.into_iter() {
            vec_idcert.push(cert);
        }
        Ok(vec_idcert)
    }

    // TODO: Test discover_services and discover_service
    /// Fetch a list of all services that the actor specified in the `actor_fid` argument has made
    /// discoverable.
    ///
    /// ## Parameters
    ///
    /// `limit`: How many results to return at maximum. Omitting this value will return all existing
    /// results.
    pub async fn discover_services(
        &self,
        actor_fid: &FederationId,
        limit: Option<u32>,
        instance_url: &Url,
    ) -> HttpResult<Vec<Service>> {
        let request_url = instance_url
            .join(DISCOVER_SERVICE_ALL.path)?
            .join(&actor_fid.to_string())?;
        let mut request = self
            .client
            .request(DISCOVER_SERVICE_ALL.method.clone(), request_url);
        if let Some(limit) = limit {
            request = request.body(
                json!({
                    "limit": limit
                })
                .to_string(),
            );
        }
        let response = request.send().await;
        HttpClient::handle_response::<Vec<Service>>(response).await
    }

    /// Fetch a list of services an actor is registered with, filtered by `service_name`.
    ///
    /// ## Parameters
    ///
    /// `limit`: Whether to limit the amount of returned results. Not specifying a limit will
    /// return all services. Specifying a limit value of 1 will return only the primary
    /// service provider.
    pub async fn discover_service(
        &self,
        actor_fid: &FederationId,
        service_name: &ServiceName,
        limit: Option<u32>,
        instance_url: &Url,
    ) -> HttpResult<Vec<Service>> {
        let request_url =
            instance_url.join(&format!("{}{}", DISCOVER_SERVICE_SINGULAR.path, actor_fid))?;
        let mut request = self
            .client
            .request(DISCOVER_SERVICE_SINGULAR.method.clone(), request_url);
        if let Some(limit) = limit {
            request = request.body(
                json!({
                    "limit": limit,
                    "name": service_name
                })
                .to_string(),
            );
        } else {
            request = request.body(
                json!({
                    "name": service_name
                })
                .to_string(),
            );
        }
        let response = request.send().await;
        HttpClient::handle_response::<Vec<Service>>(response).await
    }

    /// Retrieve the maximum upload size for encrypted private key material, in bytes.
    pub async fn get_pkm_upload_size_limit(&self, instance_url: &Url) -> HttpResult<u64> {
        let request = self.client.request(
            GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT.method.clone(),
            instance_url.join(GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT.path)?,
        );
        let response = request.send().await;
        HttpClient::handle_response::<u64>(response).await
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

#[cfg(feature = "serde")]
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
/// Response from querying a polyproto `.well-known` endpoint.
// TODO: move into submodule
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
