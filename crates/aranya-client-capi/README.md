# Aranya Client C API

## Generating the shared library

To generate the Aranya client shared library, enter this command from the project root:
`cargo make build-capi`

## Generating the aranya-client.h header

`./output/aranya-client.h` will be generated whenever aranya-client-capi is built.

## Generating Doxygen Docs

To generate the Doxygen docs, enter this command in the current directory:
`doxygen`

The docs will be generated in the `./docs/` folder.

Open the `./docs/index.html` file in a browser to view the docs.
