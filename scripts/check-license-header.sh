#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Execute this from the project root:
# $: ./scripts/check-license-header.sh
npx github:viperproject/check-license-header#v2 check -c .github/license-check/config.json --path .