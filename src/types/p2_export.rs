// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use super::ResourceAccessProperties;

/// A P2Export data export.
pub struct P2Export<M> {
    /// Generic messages
    messages: MessageBatches<M>,
}

pub struct MessageBatches<M> {
    rawr: Option<RawrContent<M>>,
}

pub struct RawrContent<M> {
    resources: Vec<M>,
    access_properties: HashMap<String, ResourceAccessProperties>,
}

#[cfg(feature = "reqwest")]
mod reqwest {
    use crate::errors::InvalidInput;

    use super::P2Export;

    impl<M> TryFrom<P2Export<M>> for reqwest::multipart::Form {
        type Error = InvalidInput;
        // TODO
        fn try_from(value: P2Export<M>) -> Result<Self, Self::Error> {
            todo!()
        }
    }
}
