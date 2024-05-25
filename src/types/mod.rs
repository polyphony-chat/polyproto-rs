// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod challenge_string;
pub mod federation_id;

pub use challenge_string::*;
pub use federation_id::*;

pub mod routes {
    pub struct Route {
        pub method: http::Method,
        pub path: &'static str,
    }

    pub mod core {
        pub mod v1 {
            use super::super::Route;

            pub static GET_CHALLENGE_STRING: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/challenge",
            };

            pub static ROTATE_SERVER_IDENTITY_KEY: Route = Route {
                method: http::Method::PUT,
                path: "/.p2/core/v1/key/server",
            };

            pub static GET_SERVER_PUBLIC_IDCERT: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/idcert/server",
            };

            pub static GET_SERVER_PUBLIC_KEY: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/key/server",
            };

            pub static GET_ACTOR_IDCERTS: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/idcert/actor/",
            };

            pub static UPDATE_SESSION_IDCERT: Route = Route {
                method: http::Method::PUT,
                path: "/.p2/core/v1/session/idcert/extern",
            };

            pub static DELETE_SESSION: Route = Route {
                method: http::Method::DELETE,
                path: "/.p2/core/v1/session/",
            };

            pub static ROTATE_SESSION_IDCERT: Route = Route {
                method: http::Method::POST,
                path: "/.p2/core/v1/session/idcert",
            };

            pub static UPLOAD_ENCRYPTED_PKM: Route = Route {
                method: http::Method::POST,
                path: "/.p2/core/v1/session/keymaterial",
            };

            pub static GET_ENCRYPTED_PKM: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/session/keymaterial",
            };

            pub static DELETE_ENCRYPTED_PKM: Route = Route {
                method: http::Method::DELETE,
                path: "/.p2/core/v1/session/keymaterial",
            };

            pub static GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT: Route = Route {
                method: http::Method::OPTIONS,
                path: "/.p2/core/v1/session/keymaterial",
            };
        }
    }
}
