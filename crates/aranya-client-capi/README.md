# Aranya Client C API

This crate contains the C API bindings for `aranya-client`, and is used to develop applications for Aranya.

## Building

There are several ways to compile the library to link into a C project:

-   `cargo make capi` will compile the include header, doxygen documentation, and the library file.
-   `cargo make capi-header` will only compile the include header.
-   `cargo make capi-docs` will only compile the doxygen documents.
-   `cargo make capi-lib` will only compile the library file.

Additionally, the shared library supports a number of features, which can be enabled or disabled by adding `-feature` to `capi` or `capi-lib`.
Currently supported features are:

-   `capi` / `capi-lib` will compile with all features enabled.
-   `capi-default` / `capi-lib-default` will compile with default features.
-   `capi-preview` / `capi-lib-preview` will compile with preview features (includes AFC).
-   `capi-experimental` / `capi-lib-experimental` will compile with preview and experimental features (includes AFC and AQC).

Note that the header file and documentation only have one build task. In order to enable certain features, you must also define certain macros:

-   `ENABLE_ARANYA_PREVIEW` must be enabled to use preview features (includes AFC).
    -   `ENABLE_ARANYA_AFC` enables Aranya Fast Channels functionality.
-   `ENABLE_ARANYA_EXPERIMENTAL` must be enabled to use experimental features (includes AQC).
    -   `ENABLE_ARANYA_AQC` enables Aranya QUIC Channels functionality.

## Shared Library

Running `cargo make capi-lib` will compile the shared library file that you can then link into a C application when developing for Aranya.

## Include Header

Running `cargo make capi-header` will generate `aranya-client.h` in the `./output/` folder, which provides definitions for the types and methods available.

## API Documentation

Running `cargo make capi-docs` will generate documentation in the `./docs/` folder, which contains documentation on available types and methods.

You can then open `./docs/index.html` in a browser to view the docs.

Note that generating documentation requires that [doxygen](https://www.doxygen.nl/index.html) be installed.
