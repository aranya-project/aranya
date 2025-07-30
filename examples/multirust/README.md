# Multi-node Rust Example

## Running the example

From `examples/multirust` directory.

Build images:

```sh
docker buildx bake --allow=fs.read="$(realpath ../../)"
```

Run the containers:

```sh
docker compose up --abort-on-container-exit
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
