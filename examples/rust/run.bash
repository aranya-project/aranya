#!/usr/bin/env bash

# Copyright (c) SpiderOak, Inc. All rights reserved.

# Change into the example directory if needed
SCRIPT_PATH=$(dirname "$0")
cd $SCRIPT_PATH

# Build and run the example
cargo build --release
./target/release/aranya-example
