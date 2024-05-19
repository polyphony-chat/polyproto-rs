// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub fn init_logger() {
    std::env::set_var("RUST_LOG", "trace");
    env_logger::builder()
        .filter_module("crate", log::LevelFilter::Trace)
        .is_test(true)
        .try_init()
        .unwrap_or(());
}
