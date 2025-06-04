# Example Rust Application

This crate contains example code showing how to use Aranya in a Rust application.

This example shows how to use the [`aranya-client`](../../crates/aranya-client) library to:
- Setup a team
- Sync Aranya graphs
- Create an AQC (Aranya QUIC) channel
- Send encrypted data between peers

During setup, the example application starts an instance of the [`aranya-daemon`](../../crates/aranya-daemon) for each Aranya device in the background. [The daemon](https://aranya-project.github.io/aranya-docs/technical-apis/rust-api/#aranya-daemon) handles low-level operations such as automatically syncing graph states between different devices so that [the client](https://aranya-project.github.io/aranya-docs/technical-apis/rust-api/#aranya-client) can focus on the operations it wants to perform on the team.

## Running the example
We've provided a few different ways to run the Aranya example.

## 1. Running the example with cargo-make
Install the [Rust toolchain](https://www.rust-lang.org/tools/install), this will install the toolchain manager `rustup`, the rust compiler `rustc` and package manager/build tool `cargo`.

Install [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation) (v0.37.23).

```bash
# First, download the source code from this repository:
$ git clone git@github.com:aranya-project/aranya.git

# Change into the directory
$ cd aranya

# Run the make command
$ cargo make run-rust-example
```

This starts the example and automatically runs through the aforementioned
steps.

## 2. Building and running the example manually from the repo
Install the [Rust toolchain](https://www.rust-lang.org/tools/install), this will install the toolchain manager `rustup`, the rust compiler `rustc` and package manager/build tool `cargo`.

```bash
# First, download the source code from this repository:
$ git clone git@github.com:aranya-project/aranya.git

# Change into the directory
$ cd aranya/examples/rust

# Build the binary
$ cargo build --release

# Run the binary:
$ target/release/aranya-example
```

You can optionally set the [tracing log level](https://docs.rs/tracing/latest/tracing/struct.Level.html#impl-Level) by adding a prefix to the command:
```bash
# Run the binary with extra logging:
$ ARANYA_EXAMPLE=info target/release/aranya-example
```
