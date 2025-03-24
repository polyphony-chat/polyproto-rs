// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
mod registration_required {
    use serde_json::json;

    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
        /// Add a service to the list of discoverable services. The service must be a valid [Service].
        /// If the service provider is the first to provide this service, or if the [Service] has a
        /// property of `primary` set to `true`, the service will be marked as the primary service
        /// provider for this service.
        ///
        /// The server will return a [Vec] of all [Service]s affected
        /// by this operation. This [Vec] will have a length of 1, if no other service entry was
        /// affected, and a length of 2 if this new service entry has replaced an existing one in the
        /// role of primary service provider.
        pub async fn add_discoverable_service(
            &self,
            service: &Service,
        ) -> HttpResult<Vec<Service>> {
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
}

mod registration_not_required {
    use serde_json::json;

    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {}

    impl HttpClient {
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
    }
}
