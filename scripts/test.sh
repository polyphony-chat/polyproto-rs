#!/bin/sh
cargo nextest run --features="gateway, types, reqwest" --failure-output final --no-fail-fast
