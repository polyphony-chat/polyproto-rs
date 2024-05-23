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
        use super::Route;

        pub static GET_CHALLENGE_STRING: Route = Route {
            method: http::Method::GET,
            path: "/.p2/core/v1/challenge",
        };

        pub static ROTATE_SERVER_IDENTITY_KEY: Route = Route {
            method: http::Method::PUT,
            path: "/.p2/core/v1/key/server",
        };

        // TODO: Other routes
    }
}
