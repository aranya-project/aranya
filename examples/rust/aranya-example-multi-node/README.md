# Aranya Multi Node Example

An example that runs each Aranya device as a stand-alone executable.

# How To Run The Example

In this workspace, run:
`cargo make run-rust-example-multi-node`

# How To Run The Example On Multiple Nodes

Copy the following artifacts onto each node:
- `example.env` - an environment file for loading shared configuration info such as IP addresses into executables
- `aranya-daemon` - the Aranya daemon executable
- `aranya-example-multi-node-<node variant>` - the team member's Aranya client executable

For example, the `owner` device would copy the `aranya-example-multi-node-owner` executable from the `target/release/` folder onto the corresponding machine acting as the owner on the team.

Once the artifacts have been copied onto each machine, source the environment file into the current environment on each machine: `. example.env`

Create a `config.toml` configuration file for each daemon before starting them:
[example daemon config file](https://github.com/aranya-project/aranya/blob/main/crates/aranya-daemon/src/example.toml)

Start the Aranya daemon `aranya-daemon` executable and Aranya client executable on each machine on the network at the same time. E.g. on the owner machine run:
`aranya-daemon --config <path to daemon config file>`
`aranya-example-multi-node-owner --uds-sock <path to daemon's unix domain socket API>`

Each node's executable will load information such as IP addresses from the environment file and perform operations via the Aranya client such as setting up the team and AQC channels.
