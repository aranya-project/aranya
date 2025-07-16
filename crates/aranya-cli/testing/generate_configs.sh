#!/bin/bash


for i in {1..5}; do
    mkdir -p /tmp/aranya$i/{run,state,cache,logs,config}
done

# Read the environment variables from the env file
while IFS='=' read -r key value; do
    export "$key"="$value"
done < env

# Generate config files for each daemon
for i in {1..5}; do
    daemon_var="daemon_owner_$i"
    daemon_addr=$(eval echo \$$daemon_var)
    
    cat > "config_daemon$i.json" << EOF
{
    "name": "test_daemon_$i",
    "runtime_dir": "/tmp/aranya$i/run",
    "state_dir": "/tmp/aranya$i/state", 
    "cache_dir": "/tmp/aranya$i/cache",
    "logs_dir": "/tmp/aranya$i/logs",
    "config_dir": "/tmp/aranya$i/config",
    "sync_addr": "$daemon_addr",
    "quic_sync": {}
}
EOF
    echo "Generated config_daemon$i.json with sync_addr: $daemon_addr"
done

echo "All config files generated successfully!" 