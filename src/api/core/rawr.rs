// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
mod registration_required {
    use http::StatusCode;

    use crate::api::matches_status_code;
    use crate::types::{Resource, ResourceInformation};

    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
        pub async fn list_uploaded_rawr_resources() -> HttpResult<Vec<Resource>> {
            todo!()
        }

        pub async fn update_rawr_resource_access() -> HttpResult<()> {
            todo!()
        }

        pub async fn upload_rawr_resource(resource: &Resource, rid: &str) -> HttpResult<()> {
            todo!()
        }

        /// Delete a resource by its resource id (rid).
        pub async fn delete_rawr_resource(&self, rid: &str) -> HttpResult<()> {
            let request = self
                .client
                .client
                .request(
                    DELETE_RESOURCE.method,
                    self.instance_url.join(DELETE_RESOURCE.path)?.join(rid)?,
                )
                .bearer_auth(&self.token);
            let response = request.send().await?;
            matches_status_code(&[StatusCode::NO_CONTENT, StatusCode::OK], response.status())
        }

        pub async fn get_own_rawr_resource_info_by_id() -> HttpResult<ResourceInformation> {
            todo!()
        }
    }
}

mod registration_not_required {
    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {}

    impl HttpClient {
        pub async fn get_rawr_resource_by_id() -> HttpResult<Vec<u8>> {
            todo!()
        }
    }
}
