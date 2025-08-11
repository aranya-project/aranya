# Aranya Multi Node Example

An example that runs each Aranya device as a stand-alone executable.

# How To Run The Example

In this directory, run:
`./run.bash`

Or, install `cargo make` then run:
`cargo make run-rust-example-multi-node`

# How To Run The Example On Multiple Nodes

Copy the following artifacts onto each node:
- `example.env`
- `daemon`
- `aranya-example-multi-node-<node variant>`

For example, the `owner` device would copy the `aranya-example-multi-node-owner` executable from the `target/release/` folder onto the corresponding machine acting as the owner on the team.

Once the artifacts have been copied onto each machine, source the environment file into the current environment on each machine: `. example.env`

Each node's executable will load information such as IP addresses from the environment file and automatically start the daemon process in the background while performing operations via the Aranya client such as setting up the team and AQC channels.
