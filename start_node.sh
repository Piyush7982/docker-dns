#!/bin/bash

# Exit on any error
set -e

# Function to cleanup on exit
cleanup() {
    echo "Stopping blockchain node..."
    if [ ! -z "$NODE_PID" ]; then
        kill $NODE_PID 2>/dev/null || true
        wait $NODE_PID 2>/dev/null || true
    fi
    # Kill any remaining python processes for this node
    pkill -f "python3.*blockchain_node.py.*$NODE_ID" 2>/dev/null || true
    echo "Node stopped."
    exit 0
}

# Set up trap for cleanup
trap cleanup SIGINT SIGTERM

NODE_TYPE=$1
NODE_ID=$2
PORT=$3
IP_ADDRESS=$4

# Check for required commands
for cmd in python3 pip3 ip curl; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: Required command '$cmd' is not installed."
        exit 1
    fi
done

if [ -z "$NODE_TYPE" ] || [ -z "$NODE_ID" ] || [ -z "$PORT" ]; then
    echo "Usage: $0 <node_type> <node_id> <port> [ip_address]"
    echo "  node_type: blockchain, validator, or client"
    echo "  node_id: Unique identifier for this node"
    echo "  port: Port number to run the node on"
    echo "  ip_address: (Optional) IP address to assign to this node"
    exit 1
fi

# Validate port number
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
    echo "Error: Invalid port number. Must be between 1024 and 65535."
    exit 1
fi

# Validate node type
case $NODE_TYPE in
    blockchain|validator|client)
        ;;
    *)
        echo "Error: Invalid node type '$NODE_TYPE'"
        echo "Valid types: blockchain, validator, or client"
        exit 1
        ;;
esac

# Configure IP address if provided
if [ ! -z "$IP_ADDRESS" ]; then
    echo "Configuring network interface with IP: $IP_ADDRESS"
    
    # Validate IP address format
    if ! echo "$IP_ADDRESS" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' > /dev/null; then
        echo "Error: Invalid IP address format"
        exit 1
    fi
    
    # Get the interface name (usually eth0 in Docker)
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
    if [ -z "$INTERFACE" ]; then
        echo "Error: Could not determine network interface"
        exit 1
    fi
    
    # Add IP address to interface
    if ! ip addr add $IP_ADDRESS/24 dev $INTERFACE 2>/dev/null; then
        echo "Warning: Failed to add IP address. It might already be configured."
    fi
    
    echo "Network interface configured:"
    ip addr show $INTERFACE
    
    # Test connectivity to a few known IPs
    echo "Testing network connectivity..."
    for TEST_IP in "192.168.1.10" "192.168.1.20"; do
        if [ "$TEST_IP" != "$IP_ADDRESS" ]; then
            if ping -c 1 -W 1 $TEST_IP >/dev/null 2>&1; then
                echo "  ✓ Can reach $TEST_IP"
            else
                echo "  ✗ Cannot reach $TEST_IP"
            fi
        fi
    done
fi

echo "Starting $NODE_TYPE node with ID $NODE_ID on port $PORT..."

# Check if required Python files exist
for file in blockchain_node.py dns_client.py connect_peers.sh; do
    if [ ! -f "$file" ]; then
        echo "Error: Required file '$file' not found"
        exit 1
    fi
done

# Make sure connect_peers.sh is executable
chmod +x connect_peers.sh

# Start the node based on its type
case $NODE_TYPE in
    blockchain)
        python3 blockchain_node.py --id $NODE_ID --port $PORT &
        NODE_PID=$!
        echo "Blockchain node started with PID: $NODE_PID"
        
        # Check if process started successfully
        sleep 2
        if ! kill -0 $NODE_PID 2>/dev/null; then
            echo "Error: Process failed to start"
            exit 1
        fi
        
        # Wait for node to initialize
        sleep 5
        
        # Connect to peers
        echo "Connecting to peers..."
        ./connect_peers.sh
        
        # Wait for the node process
        echo "Node is running. Press Ctrl+C to stop."
        wait $NODE_PID
        ;;
    validator)
        python3 blockchain_node.py --id $NODE_ID --port $PORT --validator &
        NODE_PID=$!
        echo "Validator node started with PID: $NODE_PID"
        
        # Check if process started successfully
        sleep 2
        if ! kill -0 $NODE_PID 2>/dev/null; then
            echo "Error: Process failed to start"
            exit 1
        fi
        
        # Wait for node to initialize
        sleep 5
        
        # Connect to peers
        echo "Connecting to peers..."
        ./connect_peers.sh
        
        # Wait for the node process
        echo "Node is running. Press Ctrl+C to stop."
        wait $NODE_PID
        ;;
    client)
        # For client, determine which nodes to connect to based on current network
        BLOCKCHAIN_NODES=""
        for NODE_IP in "192.168.1.10" "192.168.1.11" "192.168.1.12" "192.168.1.20" "192.168.1.21"; do
            if ping -c 1 -W 1 $NODE_IP >/dev/null 2>&1; then
                if curl -s "http://$NODE_IP:$PORT/node/status" >/dev/null 2>&1; then
                    BLOCKCHAIN_NODES="$BLOCKCHAIN_NODES http://$NODE_IP:$PORT"
                    echo "Found accessible node at $NODE_IP"
                fi
            fi
        done
        
        if [ -z "$BLOCKCHAIN_NODES" ]; then
            echo "No blockchain nodes found to connect to! Please specify manually."
            python3 dns_client.py --id $NODE_ID
        else
            echo "Connecting to blockchain nodes: $BLOCKCHAIN_NODES"
            python3 dns_client.py --nodes $BLOCKCHAIN_NODES --id $NODE_ID
        fi
        ;;
esac 