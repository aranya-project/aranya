#!/usr/bin/env bash

# Copyright (c) SpiderOak, Inc. All rights reserved.

cargo install --locked cargo-generate
cd examples/rust
cargo generate aranya-project/aranya templates/aranya-example
