#!/bin/bash

# Exit on any error
set -e

# Check for required commands
for cmd in curl hostname; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: Required command '$cmd' is not installed."
        exit 1
    fi
done

# connect_peers.sh - Script to connect a node to all other nodes in the network

# Define all node IPs in the network
BLOCKCHAIN_NODE_IPS=("192.168.1.10" "192.168.1.11" "192.168.1.12")
VALIDATOR_NODE_IPS=("192.168.1.20" "192.168.1.21")
ALL_NODE_IPS=("${BLOCKCHAIN_NODE_IPS[@]}" "${VALIDATOR_NODE_IPS[@]}")
PORT=5000

# Get current node's IP address
CURRENT_IP=$(hostname -I | awk '{print $1}')
if [ -z "$CURRENT_IP" ]; then
    echo "Error: Could not determine current IP address"
    exit 1
fi
echo "Current node IP: $CURRENT_IP"

# Function to check if a node is responsive
check_node() {
    local node_ip=$1
    local port=$2
    local max_retries=3
    local retry=0
    
    while [ $retry -lt $max_retries ]; do
        if curl -s -m 2 "http://$node_ip:$port/node/status" >/dev/null 2>&1; then
            return 0
        fi
        retry=$((retry + 1))
        [ $retry -lt $max_retries ] && sleep 1
    done
    return 1
}

# Connect to all other nodes
echo "Connecting to other nodes in the network..."
CONNECTED_NODES=0
FAILED_NODES=0

for NODE_IP in "${ALL_NODE_IPS[@]}"; do
    if [ "$NODE_IP" != "$CURRENT_IP" ]; then
        echo -n "Connecting to: $NODE_IP:$PORT ... "
        
        if check_node "$NODE_IP" "$PORT"; then
            # Try to register peer
            RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
                 -d "{\"peer\": \"http://$NODE_IP:$PORT\"}" \
                 "http://localhost:$PORT/peers/register")
            
            if echo "$RESPONSE" | grep -q "success"; then
                echo "✓ Connected"
                CONNECTED_NODES=$((CONNECTED_NODES + 1))
            else
                echo "✗ Registration failed"
                FAILED_NODES=$((FAILED_NODES + 1))
            fi
        else
            echo "✗ Node not responsive"
            FAILED_NODES=$((FAILED_NODES + 1))
        fi
    else
        echo "Skipping self ($CURRENT_IP)"
    fi
done

# If this is a validator node, register with all blockchain nodes
IS_VALIDATOR=$(ps aux | grep "blockchain_node.py" | grep "validator" | wc -l)
if [ $IS_VALIDATOR -gt 0 ]; then
    NODE_ID=$(ps aux | grep "blockchain_node.py" | grep "validator" | grep -o "\-\-id [^ ]*" | cut -d ' ' -f2)
    if [ -z "$NODE_ID" ]; then
        echo "Error: Could not determine validator node ID"
        exit 1
    fi
    
    echo "This is validator node: $NODE_ID. Registering with blockchain nodes..."
    VALIDATOR_REGISTRATIONS=0
    VALIDATOR_FAILURES=0
    
    for BC_NODE_IP in "${BLOCKCHAIN_NODE_IPS[@]}"; do
        if [ "$BC_NODE_IP" != "$CURRENT_IP" ]; then
            echo -n "Registering validator $NODE_ID with blockchain node: $BC_NODE_IP ... "
            
            if check_node "$BC_NODE_IP" "$PORT"; then
                RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
                     -d "{\"validator_id\": \"$NODE_ID\"}" \
                     "http://$BC_NODE_IP:$PORT/validators/register")
                
                if echo "$RESPONSE" | grep -q "success"; then
                    echo "✓ Registered"
                    VALIDATOR_REGISTRATIONS=$((VALIDATOR_REGISTRATIONS + 1))
                else
                    echo "✗ Registration failed"
                    VALIDATOR_FAILURES=$((VALIDATOR_FAILURES + 1))
                fi
            else
                echo "✗ Node not responsive"
                VALIDATOR_FAILURES=$((VALIDATOR_FAILURES + 1))
            fi
        fi
    done
    
    echo "Validator registration summary:"
    echo "  Successful registrations: $VALIDATOR_REGISTRATIONS"
    echo "  Failed registrations: $VALIDATOR_FAILURES"
fi

echo "Peer connection process completed!"
echo "  Successful connections: $CONNECTED_NODES"
echo "  Failed connections: $FAILED_NODES"

# Exit with error if no connections were made
if [ $CONNECTED_NODES -eq 0 ]; then
    echo "Error: Failed to connect to any nodes"
    exit 1
fi 