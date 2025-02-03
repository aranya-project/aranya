# Example Rust Application

This crate contains example code showing how to use Aranya in a Rust application. In order to set it up, you'll need to install [`cargo-generate`](https://crates.io/crates/cargo-generate), which will allow you to create a new Rust project with some boilerplate example code that you can then modify as needed.

This example shows how to use the [`aranya-client`](../../crates/aranya-client) library to:
- Setup a team
- Sync Aranya graphs
- Create an Aranya Fast Channel
- Send encrypted data between peers

During setup, the example application starts an instance of the [`aranya-daemon`](../../crates/aranya-daemon) for each Aranya user in the background. The daemon handles low-level operations such as syncing between different users so that the client can focus on the operations it wants to perform on the team.

# Generate a New Project

Install [cargo-generate](https://crates.io/crates/cargo-generate) using cargo (you should have the [Rust toolchain](https://www.rust-lang.org/tools/install) installed):
```
cargo install cargo-generate
```

Then, generate a new workspace from the template, which will prompt you for the name of the new project you wish to create:
```
cargo generate aranya-project/aranya templates/aranya-example
```

# Building the Example

You can then build your new project (release mode will provide faster binaries):
```
cargo build --release
```

# Running the Example

Finally, you can run your newly created project[^1]:
```
target/release/aranya-example
```

You can optionally set the [tracing log level](https://docs.rs/tracing/latest/tracing/struct.Level.html#impl-Level) by adding a prefix to the command:
```
ARANYA_EXAMPLE=info target/release/aranya-example
```

[^1]: "aranya-example" is the default binary name, you can change it in the `[[bin]]` section of the `Cargo.toml`.