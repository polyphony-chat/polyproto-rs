// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
mod registration_required {
    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {}
}

mod registration_not_required {
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
