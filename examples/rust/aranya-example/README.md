# Example Rust Application

This crate contains example code showing how to use Aranya in a Rust application.

This example shows how to use the [`aranya-client`](../../crates/aranya-client) library to:
- Setup a team
- Sync Aranya graphs
- Create an AQC (Aranya QUIC) channel
- Send encrypted data between peers
- Create and AFC (Aranya Fast Channel) and encrypt/decrypt data with open/seal operations.

During setup, the example application starts an instance of the [`aranya-daemon`](../../crates/aranya-daemon) for each Aranya device in the background. [The daemon](https://aranya-project.github.io/aranya-docs/technical-apis/rust-api/#aranya-daemon) handles low-level operations such as automatically syncing graph states between different devices so that [the client](https://aranya-project.github.io/aranya-docs/technical-apis/rust-api/#aranya-client) can focus on the operations it wants to perform on the team.

# Running the example with cargo-make
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
