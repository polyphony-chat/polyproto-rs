// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use super::*;
mod registration_required {
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
    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {}

    impl HttpClient {
        /// Retrieve the maximum upload size for encrypted private key material, in bytes.
        pub async fn get_pkm_upload_size_limit(&self, instance_url: &Url) -> HttpResult<u64> {
            let request = self.client.request(
                GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT.method.clone(),
                instance_url.join(GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT.path)?,
            );
            let response = request.send().await;
            HttpClient::handle_response::<u64>(response).await
        }
    }
}
