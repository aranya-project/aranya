# Example Rust Application

An example of how to use the `aranya-client` library to:
- Setup a team
- Sync Aranya graphs
- Create an Aranya Fast Channel
- Send encrypted data between peers

During setup, the example application starts an instance of the `aranya-daemon` for each Aranya user in the background. The daemon automatically handles syncing Aranya graph states between peers to the Aranya client can focus on the operations it wants to perform on the team.

# Building the example

`cargo build`

# Running the example

`cargo run`

# Running the example with tracing

Set the desired tracing level with the `ARANYA_EXAMPLE` environment variable:
`ARANYA_EXAMPLE=info cargo run`

# Create a new project based on this example with `cargo-generate`:

`cargo generate https://github.com/aranya-project/aranya crates/aranya-example`
