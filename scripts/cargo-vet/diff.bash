#!/usr/bin/env bash

set -aeuo pipefail

if command -v shellcheck; then
	shellcheck "${0}"
fi

# cargo vet diff
diff=${DIFF:-1}
# cargo vet certify
certify=${CERTIFY:-1}

pushd ../../
cargo vet check | while read -r line ; do
    echo "$line"
    # diff
    if [ "${diff}" == "1" ]; then
        eval "$(echo "$line" | grep "cargo vet diff" | awk '{print $1 " " $2 " " $3 " " $4 " " $5 " " $6}')"
        eval "$(echo "$line" | grep "cargo vet inspect" | awk '{print $1 " " $2 " " $3 " " $4 " " $5}')"
    fi
    # certify
    if [ "${certify}" == "1" ]; then
        eval "$(echo "$line" | grep "cargo vet diff" | awk '{print "cargo vet certify --accept-all " $4 " " $5 " " $6}')"
        eval "$(echo "$line" | grep "cargo vet inspect" | awk '{print "cargo vet certify --accept-all " $4 " " $5}')"
    fi
done
popd
