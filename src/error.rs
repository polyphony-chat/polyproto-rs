// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use thiserror::Error;

use crate::SignatureType;

#[derive(Debug, Error, PartialEq, Eq, Clone, Hash)]
pub enum Error {
    #[error("Signature type mismatch: {0:?} != {1:?}")]
    SignatureTypeMismatch(SignatureType, SignatureType),
}
