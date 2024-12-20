# C Application Example

This example C application shows how to use the `aranya-client-capi` C API.
Using the `run.bash` script, it starts the daemons and clients and then runs
through a scenario involving five team members.

First, a user will create the team and add the four other team members. Then,
the team will setup syncing with each other to ensure consistent state. Then,
the users work together to create an Aranya Fast Channel to send data messages
between two of the team members.

`example.c` is the example C application.

`cmake` is used to build the program and link to the `aranya-client-capi` shared library.

The `aranya-daemon` process is assumed to have been started before running the example application.

A `config.json` file is provided for configuring the `aranya-daemon` when it starts up.

# Dependencies

- [cmake](https://cmake.org/download/)
- [rust](https://www.rust-lang.org/tools/install)
- [patchelf](https://github.com/NixOS/patchelf)

# Running The Example

A `run.bash` bash script is provided to help with running the example.
Note that the script automatically starts the `aranya-daemon` executable before running the example C application.

Running the script:
`cargo make run-capi-example`

This command will also build local doxygen documentation for the
[`aranya-client-capi`](crates/aranya-client-capi/docs/). Open the
[`docs/index.html`](crates/aranya-client-c-api/docs/index.html) file in a
browser to view the docs.
