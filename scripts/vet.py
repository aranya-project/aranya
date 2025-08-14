#!/usr/bin/env python3

"""
This script makes it easier to automatically open cargo vet diffs and certify deps.

It runs `cargo vet check` with json output and handles each suggestion.
The user can press enter to open the diff for each dependency in a new browser tab.
Once the changes have been reviewed, the user should close the opened browser tab and press enter again to certify the change.
"""


import argparse
from subprocess import run, PIPE
import json


def vet(*args):
    return run(["cargo", "vet", *args], check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-inspect", dest="inspect", action="store_false", default=True)
    parser.add_argument("--no-certify", dest="certify", action="store_false", default=True)
    args = parser.parse_args()

    output = run(["cargo", "vet", "check", "--output-format=json"], stdout=PIPE)
    output = json.loads(output.stdout)

    if output["conclusion"] == "success":
        print("No changes needed!")
        return

    for suggestion in output["suggest"]["suggestions"]:
        name = suggestion["name"]
        v1 = suggestion["suggested_diff"]["from"]
        v2 = suggestion["suggested_diff"]["to"]

        if v1 == "0.0.0":
            if args.inspect: vet("inspect", name, v2)
            if args.certify: vet("certify", "--accept-all", name, v2)
        else:
            if args.inspect: vet("diff", name, v1, v2)
            if args.certify: vet("certify", "--accept-all", name, v1, v2)



if __name__ == "__main__":
    main()
