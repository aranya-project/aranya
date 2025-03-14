# Example Rust Application

This crate contains example code showing how to use Aranya in a Rust application. In order to set it up, you'll need to install [`cargo-generate`](https://crates.io/crates/cargo-generate), which will allow you to create a new Rust project with some boilerplate example code that you can then modify as needed.

This example shows how to use the [`aranya-client`](../../crates/aranya-client) library to:
- [Setup a team](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#create-team)
- [Sync Aranya graphs](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#syncer)
- [Create an Aranya Fast Channel](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#off-graph-messaging)
- [Send encrypted data between peers](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#send-messages)

During setup, the example application starts an instance of the [`aranya-daemon`](../../crates/aranya-daemon) for each Aranya device in the background. [The daemon](https://aranya-project.github.io/aranya-docs/technical-apis/rust-api/#aranya-daemon) handles low-level operations such as automatically syncing graph states between different devices so that [the client](https://aranya-project.github.io/aranya-docs/technical-apis/rust-api/#aranya-client) can focus on the operations it wants to perform on the team.

# Generate a New Project
Install the [Rust toolchain](https://www.rust-lang.org/tools/install), this will install the toolchain manager `rustup`, the rust compiler `rustc` and package manager/build tool `cargo`. 


Install [cargo-generate](https://crates.io/crates/cargo-generate) using cargo:
```
cargo install --locked cargo-generate
```

Then, generate a new project from the template, which will prompt you for the name of the new project you wish to create:
```
cargo generate aranya-project/aranya templates/aranya-example --name rust-example
```

The `--branch` option can be used with `cargo generate` to select a particular branch to generate the template from.
The `--revision` option can be used with `cargo generate` to select a particular commit to generate the template from. 

To generate a template based on the your local copy of the repository:
```
cd <repo>
cargo generate --path templates/aranya-example --name rust-example
```

# Building the Example

You can then build your new project (release mode will provide faster binaries):
```
cd rust-example
cargo build --release
```

# Running the Example

Finally, you can run your newly created project[^1]:
```
cd rust-example
target/release/aranya-example
```

You can optionally set the [tracing log level](https://docs.rs/tracing/latest/tracing/struct.Level.html#impl-Level) by adding a prefix to the command:
```
cd rust-example
ARANYA_EXAMPLE=info target/release/aranya-example
```

[^1]: "aranya-example" is the default binary name, you can change it in the `[[bin]]` section of the `Cargo.toml`.
