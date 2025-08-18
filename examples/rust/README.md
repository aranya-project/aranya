# Aranya Examples

Specific examples of how to use the Aranya client Rust API.

Each example can be built then run as a stand-alone executable.

Before running the examples, ensure [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation) is installed.

# Single-node Example

How to run the example:
`cargo make run-rust-example`

Runs an example which sets up an Aranya team with `owner`, `admin`, `operator`, `membera`, and `memberb` devices. The `operator` creates a label and assigns it to `membera` and `memberb`. The member devices use this label to create a secure AQC channel between them.

Once the secure AQC channel has been created, the devices send data both ways via the channel.

More information can be found in the [README.md](aranya-example/README.md)

# Multi-node Example

How to run the example:
`cargo make run-rust-example-multi-node`

This example is essentially the same as the single node example except that each device runs code in its own executable. It is designed to allow each executable to be easily deployed to different machines.

More information can be found in the [README.md](aranya-example-multi-node/README.md)
