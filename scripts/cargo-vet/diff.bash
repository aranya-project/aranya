#!/usr/bin/env bash

set -aeuo pipefail

if command -v shellcheck; then
	shellcheck "${0}"
fi

pushd ../../
cargo vet check | grep "cargo vet diff" | awk '{print $1 " " $2 " " $3 " " $4 " " $5 " " $6}' | while read -r line ; do eval "$line" ; done
cargo vet check | grep "cargo vet inspect" | awk '{print $1 " " $2 " " $3 " " $4 " " $5 " " $6}' | while read -r line ; do eval "$line" ; done
popd
