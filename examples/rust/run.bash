#!/usr/bin/env bash

# Copyright (c) SpiderOak, Inc. All rights reserved.

cd examples/rust
cargo build --release
target/release/aranya-example
