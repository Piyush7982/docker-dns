#!/bin/bash

# connect_peers.sh - Script to connect a node to all other nodes in the network

# Define all node IPs in the network
BLOCKCHAIN_NODE_IPS=("192.168.1.10" "192.168.1.11" "192.168.1.12")
VALIDATOR_NODE_IPS=("192.168.1.20" "192.168.1.21")
ALL_NODE_IPS=("${BLOCKCHAIN_NODE_IPS[@]}" "${VALIDATOR_NODE_IPS[@]}")
PORT=5000

# Get current node's IP address
CURRENT_IP=$(hostname -I | awk '{print $1}')
echo "Current node IP: $CURRENT_IP"

# Connect to all other nodes
echo "Connecting to other nodes in the network..."
for NODE_IP in "${ALL_NODE_IPS[@]}"; do
    if [ "$NODE_IP" != "$CURRENT_IP" ]; then
        echo "Connecting to: $NODE_IP:$PORT"
        curl -s -X POST -H "Content-Type: application/json" \
             -d "{\"peer\": \"http://$NODE_IP:$PORT\"}" \
             http://localhost:$PORT/peers/register
        
        # Check if successful
        if [ $? -eq 0 ]; then
            echo "Successfully connected to $NODE_IP"
        else
            echo "Failed to connect to $NODE_IP"
        fi
    else
        echo "Skipping self ($CURRENT_IP)"
    fi
done

# If this is a validator node, register with all blockchain nodes
IS_VALIDATOR=$(ps aux | grep "blockchain_node.py" | grep "validator" | wc -l)
if [ $IS_VALIDATOR -gt 0 ]; then
    NODE_ID=$(ps aux | grep "blockchain_node.py" | grep "validator" | grep -o "\-\-id [^ ]*" | cut -d ' ' -f2)
    echo "This is validator node: $NODE_ID. Registering with blockchain nodes..."
    
    for BC_NODE_IP in "${BLOCKCHAIN_NODE_IPS[@]}"; do
        if [ "$BC_NODE_IP" != "$CURRENT_IP" ]; then
            echo "Registering validator $NODE_ID with blockchain node: $BC_NODE_IP"
            curl -s -X POST -H "Content-Type: application/json" \
                 -d "{\"validator_id\": \"$NODE_ID\"}" \
                 http://$BC_NODE_IP:$PORT/validators/register
        fi
    done
fi

echo "Peer connection process completed!" 