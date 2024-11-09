# Aranya Client C API

## Generating the shared library

To generate the Aranya client shared library, enter this command from the project root:
`cargo make build-capi`

## Generating the aranya-client.h header

To generate the `aranya-client.h` header file, enter this command from the project root:
`cargo make build-capi-header`.

The `aranya-client.h` header file will be generated in the `./output/` folder.

## Generating Doxygen Docs

To generate the Doxygen docs, enter this command in the current directory:
`doxygen`

The docs will be generated in the `./docs/` folder.

Open the `./docs/index.html` file in a browser to view the docs.
