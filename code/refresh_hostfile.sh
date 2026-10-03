#!/bin/bash

HOSTFILE="hostfile"
NODE_SCRIPT="/share/ifi/available-nodes.sh"

# Clear or create hostfile
> "$HOSTFILE"

echo "Updating $HOSTFILE..."

# Read each node output by the script
"$NODE_SCRIPT" | while read -r node; do
    # Skip empty lines if any exist
    [ -z "$node" ] && continue

    slots=$(ssh -n -o ConnectTimeout=3 -o StrictHostKeyChecking=no "$node" nproc 2>/dev/null)

    # Check if ssh succeeded and nproc returned a number
    if [ -n "$slots" ]; then
        echo "${node} slots=${slots}" >> "$HOSTFILE"
        echo "Added ${node} with ${slots} slots"
    else
        echo "No nproc from ${node}" >&2
    fi
done

echo "Updated $HOSTFILE"