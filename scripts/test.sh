#!/bin/sh
cargo nextest run --all-features --failure-output final --no-fail-fast
