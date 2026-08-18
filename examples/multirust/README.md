# Multi-node Rust Example

## Running the example

From `examples/multirust` directory.

Build and run:

```sh
docker compose up --build --force-recreate --abort-on-container-exit
```

## Saving images for sharing

Save the three images into one tarball:

```sh
docker save aranya-multirust-{operator,member-a,member-b} | gzip > aranya-multirust-images.tar.gz
```

Load the three images into your docker context:

```sh
docker load -i aranya-multirust-images.tar.gz
```
