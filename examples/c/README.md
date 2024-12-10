# C Application Example

This example C application shows how to use the `aranya-client-capi` C API.
Using the `run.bash` script, it starts the daemons and clients and then runs
through a scenario involving five devices. For more details behind the actions
performed in this example, see the [walkthrough](../../docs/walkthrough.md).

`example.c` is the example C application.

`cmake` is used to build the program and link to the `aranya-client-capi` shared library.

The `aranya-daemon` process is assumed to have been started before running the example application.

A `config.json` file is provided for configuring the `aranya-daemon` when it starts up.

# Running The Example

A `run.bash` bash script is provided to help with running the example.
Note that the script automatically starts the `aranya-daemon` executable before running the example C application.

Running the script:
`cargo make run-capi-example`
