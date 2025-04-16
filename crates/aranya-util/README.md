# Aranya Utilities (`aranya-util`)

This internal crate provides common utility functions and types used across various Aranya components like the client, 
daemon, UDS API, and others. It includes modules for:

-   **`addr`**: Handling network addresses (hostnames, IPs, ports), including parsing, validation, DNS lookups, and conversions between types like `std::net::SocketAddr`.
-   **`util`**: General utilities, such as asynchronous filesystem operations (writing files, creating directories) with specific Unix permissions, and a helper type (`ShmPathBuf`) for validated shared memory paths.

This crate makes no promises on backwards compatibility.
