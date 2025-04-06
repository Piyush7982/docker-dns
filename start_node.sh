#!/bin/bash

NODE_TYPE=$1
NODE_ID=$2
PORT=$3
IP_ADDRESS=$4

if [ -z "$NODE_TYPE" ] || [ -z "$NODE_ID" ] || [ -z "$PORT" ]; then
    echo "Usage: $0 <node_type> <node_id> <port> [ip_address]"
    echo "  node_type: blockchain, validator, or client"
    echo "  node_id: Unique identifier for this node"
    echo "  port: Port number to run the node on"
    echo "  ip_address: (Optional) IP address to assign to this node"
    exit 1
fi

# Configure IP address if provided
if [ ! -z "$IP_ADDRESS" ]; then
    echo "Configuring network interface with IP: $IP_ADDRESS"
    # Get the interface name (usually eth0 in Docker)
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
    
    # Add IP address to interface
    ip addr add $IP_ADDRESS/24 dev $INTERFACE 2>/dev/null
    
    echo "Network interface configured:"
    ip addr show $INTERFACE
    
    # Test connectivity to a few known IPs
    echo "Testing network connectivity..."
    for TEST_IP in "192.168.1.10" "192.168.1.20"; do
        if [ "$TEST_IP" != "$IP_ADDRESS" ]; then
            ping -c 1 -W 1 $TEST_IP >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "  ✓ Can reach $TEST_IP"
            else
                echo "  ✗ Cannot reach $TEST_IP"
            fi
        fi
    done
fi

echo "Starting $NODE_TYPE node with ID $NODE_ID on port $PORT..."

# Start the node based on its type
case $NODE_TYPE in
    blockchain)
        python3 blockchain_node.py --id $NODE_ID --port $PORT &
        NODE_PID=$!
        echo "Blockchain node started with PID: $NODE_PID"
        
        # Wait for node to initialize
        sleep 5
        
        # Connect to peers
        echo "Connecting to peers..."
        ./connect_peers.sh
        
        # Bring the node back to foreground
        wait $NODE_PID
        ;;
    validator)
        python3 blockchain_node.py --id $NODE_ID --port $PORT --validator &
        NODE_PID=$!
        echo "Validator node started with PID: $NODE_PID"
        
        # Wait for node to initialize
        sleep 5
        
        # Connect to peers
        echo "Connecting to peers..."
        ./connect_peers.sh
        
        # Bring the node back to foreground
        wait $NODE_PID
        ;;
    client)
        # For client, determine which nodes to connect to based on current network
        BLOCKCHAIN_NODES=""
        for NODE_IP in "192.168.1.10" "192.168.1.11" "192.168.1.12" "192.168.1.20" "192.168.1.21"; do
            ping -c 1 -W 1 $NODE_IP >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                BLOCKCHAIN_NODES="$BLOCKCHAIN_NODES http://$NODE_IP:$PORT"
                echo "Found accessible node at $NODE_IP"
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
    *)
        echo "Unknown node type: $NODE_TYPE"
        echo "Valid types: blockchain, validator, or client"
        exit 1
        ;;
esac 