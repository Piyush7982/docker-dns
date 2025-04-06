#!/bin/bash

# This script sets up a network of blockchain nodes and connects them

# Define network configuration
BLOCKCHAIN_NODES=3
VALIDATOR_NODES=2
BASE_PORT=5000
NET_PREFIX="192.168.1"  # Network prefix for IP addresses

echo "Setting up a decentralized DNS network with:"
echo "- $BLOCKCHAIN_NODES blockchain nodes"
echo "- $VALIDATOR_NODES validator nodes"
echo

# Define IP addresses
BLOCKCHAIN_IPS=()
VALIDATOR_IPS=()

# Generate blockchain node IPs
for ((i=1; i<=$BLOCKCHAIN_NODES; i++))
do
    IP="${NET_PREFIX}.1$((i-1))"
    BLOCKCHAIN_IPS+=($IP)
done

# Generate validator node IPs
for ((i=1; i<=$VALIDATOR_NODES; i++))
do
    IP="${NET_PREFIX}.2$((i-1))"
    VALIDATOR_IPS+=($IP)
done

# Start blockchain nodes
echo "Starting blockchain nodes..."
BLOCKCHAIN_PIDS=()

for ((i=1; i<=$BLOCKCHAIN_NODES; i++))
do
    IP=${BLOCKCHAIN_IPS[$i-1]}
    
    echo "Starting blockchain node $i at $IP on port $BASE_PORT..."
    ./start_node.sh blockchain "blockchain_$i" $BASE_PORT $IP &
    BLOCKCHAIN_PIDS+=($!)
    
    # Wait a bit for the node to start
    sleep 5
done

# Start validator nodes
echo -e "\nStarting validator nodes..."
VALIDATOR_PIDS=()

for ((i=1; i<=$VALIDATOR_NODES; i++))
do
    IP=${VALIDATOR_IPS[$i-1]}
    
    echo "Starting validator node $i at $IP on port $BASE_PORT..."
    ./start_node.sh validator "validator_$i" $BASE_PORT $IP &
    VALIDATOR_PIDS+=($!)
    
    # Wait a bit for the node to start
    sleep 5
done

echo -e "\nNetwork setup completed!"
echo "Blockchain nodes running at: ${BLOCKCHAIN_IPS[@]}"
echo "Validator nodes running at: ${VALIDATOR_IPS[@]}"
echo
echo "You can now start DNS clients with:"
echo "./start_node.sh client client_1 $BASE_PORT 192.168.1.30"
echo
echo "Press Ctrl+C to shut down the network."

# Wait for all processes
wait 