#!/usr/bin/env python3

from subprocess import run, PIPE
from typing import Any
import json


def get_workspace_libs(metadata: Any):
    workspace = set(metadata["workspace_default_members"])
    for package in metadata["packages"]:
        if package["id"] not in workspace:
            continue
        if any("lib" in target["kind"] for target in package["targets"]):
            yield package


def main():
    metadata = json.loads(run(["cargo", "metadata", "--format-version=1"], stdout=PIPE).stdout)

    libs = [lib["name"] for lib in get_workspace_libs(metadata)]
    for lib in libs:
        run(["cargo", "docs-rs", "-p", lib], check=True)


if __name__ == '__main__':
    main()
