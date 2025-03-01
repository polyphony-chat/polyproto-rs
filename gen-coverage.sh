#!/bin/bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# If you do not tarpaulin installed, you need to do so before running this command. 

cargo tarpaulin --all-features --tests --verbose -o lcov --output-dir .coverage --fail-immediately --avoid-cfg-tarpaulin