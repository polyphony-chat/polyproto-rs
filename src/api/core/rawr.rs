// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
mod registration_required {
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

        pub async fn delete_rawr_resource(rid: &str) -> HttpResult<()> {
            todo!()
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
