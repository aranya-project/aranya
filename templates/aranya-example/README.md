# Example Rust Application

This is a [`cargo-generate`](https://github.com/cargo-generate/cargo-generate) template, showing how to use the [`aranya-client`](../../crates/aranya-client) library to:
- Setup a team
- Sync Aranya graphs
- Create an Aranya Fast Channel
- Send encrypted data between peers

During setup, the example application starts an instance of the [`aranya-daemon`](../../crates/aranya-daemon) for each Aranya user in the background. The daemon automatically handles syncing Aranya graph states between peers so the Aranya client can focus on the operations it wants to perform on the team.

# Generate a new workspace from this template:

Install [cargo-generate](https://github.com/cargo-generate/cargo-generate).

Generate a new project from the template, which will prompt you for the name of the new project you wish to create:
```
cargo generate aranya-project/aranya templates/aranya-example
```

# Building the example

You can then build your new project:
```
cargo build --release
```

# Running the example

Finally, you can then run the example project:
```
target/release/aranya-example
```

You can optionally set the [tracing log level](https://docs.rs/tracing/latest/tracing/struct.Level.html#impl-Level) with:
```
ARANYA_EXAMPLE=info target/release/aranya-example
```
