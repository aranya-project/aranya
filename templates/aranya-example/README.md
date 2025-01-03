# Example Rust Application

This is a `cargo-generate` template.

An example of how to use the `aranya-client` library to:
- Setup a team
- Sync Aranya graphs
- Create an Aranya Fast Channel
- Send encrypted data between peers

During setup, the example application starts an instance of the `aranya-daemon` for each Aranya user in the background. The daemon automatically handles syncing Aranya graph states between peers to the Aranya client can focus on the operations it wants to perform on the team.

# Generate a new workspace from this template:

`cargo generate aranya-project/aranya templates/aranya-example`

# Building the example

`cargo build --release`

# Running the example

`target/release/aranya-example`

# Running the example with tracing

Set the desired tracing level with the `ARANYA_EXAMPLE` environment variable:
`ARANYA_EXAMPLE=info target/release/aranya-example`
