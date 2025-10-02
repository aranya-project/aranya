# Overview

This folder defines a container for building/running Aranya examples inside a GitHub Codespace.

`rust:latest` is used as the base container in the `Dockerfile` because it includes all the tools needed to build Rust code out of the box without any additional configuration.

# Prerequisites

Ensure that GitHub Codespaces are enabled for your organization and/or GitHub account.
Confirm this by checking the repository `Settings->Codespaces` tab and your account settings.

# Creating The Codespace

- Navigate to the branch of the repo you would like to create a Codespace for.
- Click the `Code` dropdown, then click on the `Codespaces` tab.
- Click `...`->`New with options`
- Recommend creating a codespace with at least 8 cores on the desired branch of the repo.

# Running The Aranya Rust Example

To run the Aranya Rust example inside a codespace:
- Start the Codespace
- Once the Codespace has initialized, select the terminal so you can start entering commands. If you are unable to run commands in the terminal, open a new terminal in the IDE.
- Execute the following to run the Rust example:
```
cd examples/rust
./run.bash
```

# Cost Saving Recommendations

Please stop/delete the Codespace when it is no longer in use to reduce costs.
