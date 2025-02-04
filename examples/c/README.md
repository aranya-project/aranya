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

Note, we have tested using the specified versions. Other versions of these
tools may also work.

- [cmake](https://cmake.org/download/) (v3.31)
- [rust](https://www.rust-lang.org/tools/install) (find version info in the
[rust-toolchain.toml](../../rust-toolchain.toml))
- [patchelf](https://github.com/NixOS/patchelf) (v0.18)

# Running The Example

First, download the source code from this repository:

`$ git clone git@github.com:aranya-project/aranya.git`

A `run.bash` bash script is provided to help with running the example.
Note that the script automatically starts the `aranya-daemon` executable before
running the example C application.

Running the script:

```bash
$ cd aranya
$ cargo make run-capi-example
```

This starts the example and automatically runs through the aforementioned
steps. This will also build local doxygen documentation for the
[`aranya-client-capi`](crates/aranya-client-capi/docs/). Open the
[`docs/index.html`](crates/aranya-client-c-api/docs/index.html) file in a
browser to view the docs.
