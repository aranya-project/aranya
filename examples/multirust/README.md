# Multi-node Rust Example

## Running the example

From `examples/multirust` directory:

```sh
docker buildx bake --allow=fs.read="$(realpath ../../)" && docker compose up --abort-on-container-exit
```

## Saving containers for sharing

```sh
docker save aranya-multirust-{operator,member-a,member-b} | gzip > aranya-multirust-images.tar.gz
```

```sh
docker load -i aranya-multirust-images.tar.gz
```
