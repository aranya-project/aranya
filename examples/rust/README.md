# Example Rust Application

This crate contains example code showing how to use Aranya in a Rust application.

This example shows how to use the [`aranya-client`](../../crates/aranya-client) library to:
- [Setup a team](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#create-team)
- [Sync Aranya graphs](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#syncer)
- [Create an Aranya Fast Channel](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#off-graph-messaging)
- [Send encrypted data between peers](https://aranya-project.github.io/aranya-docs/getting-started/walkthrough/#send-messages)

During setup, the example application starts an instance of the [`aranya-daemon`](../../crates/aranya-daemon) for each Aranya device in the background. [The daemon](https://aranya-project.github.io/aranya-docs/technical-apis/rust-api/#aranya-daemon) handles low-level operations such as automatically syncing graph states between different devices so that [the client](https://aranya-project.github.io/aranya-docs/technical-apis/rust-api/#aranya-client) can focus on the operations it wants to perform on the team.

## Running the example
We've provided a few different ways to run the Aranya example.

## 1. Running the example from a script
Install the [Rust toolchain](https://www.rust-lang.org/tools/install), this will install the toolchain manager `rustup`, the rust compiler `rustc` and package manager/build tool `cargo`.

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
$ cd aranya/example/rust

# Build the binary
$ cargo build --release

# Run the binary [^1]:
$ target/release/aranya-example
```

You can optionally set the [tracing log level](https://docs.rs/tracing/latest/tracing/struct.Level.html#impl-Level) by adding a prefix to the command:
```bash
$ ARANYA_EXAMPLE=info target/release/aranya-example
```

## 3. Create a project template
You can also create a standalone project from a template:

Install the [Rust toolchain](https://www.rust-lang.org/tools/install), this will install the toolchain manager `rustup`, the rust compiler `rustc` and package manager/build tool `cargo`.

Install [cargo-generate](https://crates.io/crates/cargo-generate) using cargo:
```bash
#  Install cargo-generate
$ cargo install --locked cargo-generate
```

Navigate to your desired destination directory. Then, generate a new project from the template, which will prompt you for the name of the new project you wish to create:
```bash
# Create Aranya example project
$ cargo generate aranya-project/aranya examples/rust
```

<!-- cargo generate --path <path_to_local_template> --branch <branch_name> --name <project_name> -->

<!-- TODO: is this creating a `aranya-example` dir from the generate command??? -->

Change into the `aranya-example` directory[^1] and then you can build your new project (release mode will provide faster binaries):
```bash
# Build the binary
$ cargo build --release
```

Finally, you can run your newly created project[^1]:
```bash
# Run the binary
$ target/release/aranya-example
```

[^1]: "aranya-example" is the default binary name, you can change it in the `[[bin]]` section of the `Cargo.toml`.
