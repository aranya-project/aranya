# Example Rust Application

This crate contains example code showing how to use Aranya in a Rust application.

This example shows how to use the [`aranya-client`](../../crates/aranya-client) library to:
- [Setup a team](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#create-team)
- [Sync Aranya graphs](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#syncer)
- [Create an Aranya Fast Channel](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#off-graph-messaging)
- [Send encrypted data between peers](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#send-messages)

During setup, the example application starts an instance of the [`aranya-daemon`](../../crates/aranya-daemon) for each Aranya device in the background. [The daemon](https://aranya-project.github.io/aranya-docs/technical-apis/rust-api/#aranya-daemon) handles low-level operations such as automatically syncing graph states between different devices so that [the client](https://aranya-project.github.io/aranya-docs/technical-apis/rust-api/#aranya-client) can focus on the operations it wants to perform on the team.

## Running the example

First, download the source code from this repository:

`$ git clone git@github.com:aranya-project/aranya.git`

### Running the example script:

A `run.bash` bash script is provided to help with running the example.
Note that the script automatically starts the `aranya-daemon` executable before
running the example Rust application.

```bash
$ cd aranya
$ cargo make run-capi-example
```

This starts the example and automatically runs through the aforementioned
steps.

### Building and running the example manually

Install the [Rust toolchain](https://www.rust-lang.org/tools/install), this will install the toolchain manager `rustup`, the rust compiler `rustc` and package manager/build tool `cargo`.


Install [cargo-generate](https://crates.io/crates/cargo-generate) using cargo:
```bash
$ cargo install --locked cargo-generate
```

Then, generate a new project from the template, which will prompt you for the name of the new project you wish to create:
```bash
$ cd examples/rust
$ cargo generate aranya-project/aranya templates/aranya-example
```


Change into the `aranya-example` directory[^1] and then you can build your new project (release mode will provide faster binaries):
```bash
$ cd aranya-example
$ cargo build --release
```

Finally, you can run your newly created project[^1]:
```bash
$ target/release/aranya-example
```

You can optionally set the [tracing log level](https://docs.rs/tracing/latest/tracing/struct.Level.html#impl-Level) by adding a prefix to the command:
```
$ ARANYA_EXAMPLE=info target/release/aranya-example
```

[^1]: "aranya-example" is the default binary name, you can change it in the `[[bin]]` section of the `Cargo.toml`.
