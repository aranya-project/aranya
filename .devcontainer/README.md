# Overview

This folder defines a container for building/running Aranya examples inside a GitHub Codespace.

`rust:latest` is used as the base container in the `Dockerfile` because it includes all the tools needed to build Rust code out of the box without any additional configuration.

# Prerequisites

Ensure that GitHub Codespaces are enabled for your organization and/or GitHub account.
Confirm this by checking the repository `Settings->Codespaces` tab and your account settings.

# Running The Aranya Rust Example

To run the Aranya Rust example inside a codespace:
- Create a new Codespace and point it to the `.devcontainer` folder of this repo containing the `Dockerfile`
- Launch the Codespace
- Once the Codespace has initialized, select the terminal so you can start entering commands
- Execute `cargo make run-rust-example` to run the Rust example
