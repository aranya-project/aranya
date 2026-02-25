# Aranya Onboarding Example

An example that runs each Aranya device as a stand-alone executable (Owner and Admin) and demonstrates the onboarding procedure.
Note: The onboarding servers in this example are not part of Aranya and exist only to support the example.

# How To Run The Example

In this workspace, run:
`cargo make run-rust-example-onboarding`

# How To Run The Example

Copy the following artifacts onto each node:
- `example.env` - an environment file for loading shared configuration info such as IP addresses into executables
- `aranya-daemon` - the Aranya daemon executable
- `aranya-example-onboarding-owner` - the owner's Aranya client executable
- `aranya-example-onboarding-admin` - the admin's Aranya client executable
- `/out/daemon/owner/daemon/config.toml` - the owner's daemon configuration
- `/out/daemon/admin/daemon/config.toml` - the admin's daemon configuration

For example, the `owner` device would copy the `aranya-example-onboarding-owner` executable from the `target/release/` folder onto the corresponding machine acting as the owner on the team.

Once the artifacts have been copied onto each machine, source the environment file into the current environment on each machine: `. example.env`

Slight modification will need to be done to the configuration to match the directory locations on the machine, and the ip address to use for sync.

Start the Aranya daemon `aranya-daemon` executable and Aranya client executable on each machine on the network at the same time. E.g. on the owner machine run:
`aranya-daemon --config <path to daemon config file>`
`aranya-example-onboarding-owner --uds-sock <path to daemon's unix domain socket API>`

Each node's executable will load information such as IP addresses from the environment file and perform operations via the Aranya client such as setting up the team and AFC channels.

# Onboarding Process Steps
Step 1. Create Daemon config for Owner.

Step 2. Start Owner Daemon. [Daemon Start](src/bin/main.rs)

Step 3. Create Daemon config for Admin. [Create Daemon Config](src/bin/main.rs)

Step 4. Starting Admin Daemon. [Daemon Start](src/bin/main.rs)

Step 5. Starting Owner Client. [Client Process Spawn](src/bin/main.rs)

Step 6. Owner starts onboarding server (for transferring data to/from onboarding users) [Onboarding Server Start](src/owner/main.rs)

Step 7. Owner initializes client. [Client Init](src/owner/main.rs)

Step 8. Starting Admin Client. [Client Process Spawn](src/bin/main.rs)

Step 9. Admin starts onboarding server (for transferring data to/from owner) [Client Init](src/admin/main.rs)

Step 10. Admin initializes client. [Client Init](src/admin/main.rs)

Step 11. Admin awaits information of the team id from Owner. [Data Receive](src/admin/main.rs)

Step 12. Owner creates seed key for quic syncer. [Create Sync Seed Key](src/owner/main.rs)

Step 13. Owner creates sync configuration. [Create Sync Config](src/owner/main.rs)

Step 14. Owner creates team with create_team()* and sets up default team roles. [Team Initialization](src/owner/main.rs)
*This creates the team, returns the team_id, and adds the team to the owner client.

Step 15. Owner sends team id and seed key to the Admin user and waits for a response containing user information. [Team Id Transmission](src/owner/main.rs)

Step 16. Admin creates sync config using seed key from Owner [Create Team Config](src/admin/main.rs)

Step 17. Admin adds team with add_team()* using the team id received from Owner [Add Team](src/admin/main.rs)
*This adds the team to the admin client.

Step 18. Admin sends user information (device id and key bundle) to the Owner. [User Information Transmission](src/admin/main.rs)

Step 19. Owner receives the user information and adds Admin to the team. [Add User to Team](src/owner/main.rs)

Step 20. Owner assigns `Admin` role to Admin user. [Assign Admin Role](src/owner/main.rs)

Step 21. Admin checks for assigned admin role [Check for assigned role](src/admin/main.rs)
