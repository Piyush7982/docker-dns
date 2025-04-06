#!/bin/bash

# Check if required commands are available
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not found."
    exit 1
fi

if ! command -v pip3 &> /dev/null; then
    echo "pip3 is required but not found."
    exit 1
fi

# Install required packages if not already installed
echo "Checking for required Python packages..."
pip3 install -q flask requests cryptography web3

# Create a network with multiple nodes
echo "Starting blockchain network..."

# Determine the base IP address
HOST_IP=$(hostname -I | awk '{print $1}')
if [ -z "$HOST_IP" ]; then
    HOST_IP="127.0.0.1"
fi
echo "Using host IP: $HOST_IP"

# Number of nodes to start
TOTAL_NODES=${1:-3}
VALIDATOR_NODES=${2:-2}

if [ $VALIDATOR_NODES -gt $TOTAL_NODES ]; then
    echo "Error: Number of validator nodes cannot exceed total nodes."
    exit 1
fi

echo "Starting $TOTAL_NODES nodes with $VALIDATOR_NODES validators..."

# Kill any existing processes
pkill -f "python3 blockchain_node.py" 2>/dev/null

# Create a directory for the logs
mkdir -p logs

# Start the nodes
NODE_URLS=()
VALIDATOR_IDS=()

for i in $(seq 1 $TOTAL_NODES); do
    PORT=$((5000 + i))
    NODE_ID="node_$i"
    NODE_URL="http://$HOST_IP:$PORT"
    NODE_URLS+=("$NODE_URL")
    
    # Determine if this node should be a validator
    if [ $i -le $VALIDATOR_NODES ]; then
        VALIDATOR_FLAG="--validator"
        VALIDATOR_IDS+=("$NODE_ID")
        echo "Starting validator node $NODE_ID on port $PORT..."
    else
        VALIDATOR_FLAG=""
        echo "Starting regular node $NODE_ID on port $PORT..."
    fi
    
    # Start the node and redirect output to a log file
    python3 blockchain_node.py --port $PORT --id $NODE_ID $VALIDATOR_FLAG > "logs/$NODE_ID.log" 2>&1 &
    
    # Wait a moment to ensure the node is up
    sleep 2
done

# Wait for all nodes to start
echo "Waiting for all nodes to start..."
sleep 5

# Connect the nodes using the helper script
echo "Connecting nodes and registering validators..."
python3 connect_validators.py --nodes "${NODE_URLS[@]}" --validators "${VALIDATOR_IDS[@]}"

echo "Blockchain network is ready."
echo "Validator nodes: ${VALIDATOR_IDS[@]}"
echo "All node URLs: ${NODE_URLS[@]}"
echo "Check logs directory for node logs."

# Keep the script running to maintain the network
echo "Press Ctrl+C to stop the network."
while true; do
    sleep 1
done 