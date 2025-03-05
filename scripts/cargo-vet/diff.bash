#!/usr/bin/env bash

# This script makes it easier to automatically open cargo vet diffs and certify deps.
# It runs `cargo vet check` and loops over each `cargo vet diff` and `cargo vet inspect` command in the output.
# The user can press enter to open the diff for each dependency in a new browser tab.
# Once the changes have been reviewed, the user should close the opened browser tab and press enter again to certify the change.
#
# The default run mode will look at diffs and certify each dependency.
# DIFF=0 ./diff.bash will skip dependency diffs.
# CERTIFY=0 ./diff.bash will skip certifying dependencies.

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
