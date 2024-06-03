// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use der::Any;
use spki::ObjectIdentifier;

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct AlgorithmIdentifierOwned(spki::AlgorithmIdentifierOwned);

impl AlgorithmIdentifierOwned {
    pub fn new(oid: ObjectIdentifier, parameters: Option<Any>) -> Self {
        Self(spki::AlgorithmIdentifierOwned { oid, parameters })
    }
}

impl Deref for AlgorithmIdentifierOwned {
    type Target = spki::AlgorithmIdentifierOwned;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AlgorithmIdentifierOwned {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
