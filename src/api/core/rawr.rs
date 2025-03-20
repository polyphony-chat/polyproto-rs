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
}
