# cargo vet supply chain audits

We automatically trust `aranya-*` crates published by `aranya-project-bot` since they are published by us:
`cargo vet trust --all aranya-project-bot`

To save us time, we've imported audits from trusted 3rd parties:
https://mozilla.github.io/cargo-vet/importing-audits.html
https://github.com/mozilla/cargo-vet/blob/main/supply-chain/config.toml
https://github.com/mozilla/cargo-vet/blob/main/registry.toml
