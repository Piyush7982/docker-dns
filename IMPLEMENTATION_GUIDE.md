# Decentralized DNS on Blockchain - Implementation Guide

This guide provides step-by-step instructions for implementing the decentralized DNS system on GNS3 using Docker containers with Ubuntu, routers, and switches.

## Overview

This project implements a decentralized Domain Name System (DNS) using blockchain technology. It allows users to register domain names, update DNS records, transfer domain ownership, and resolve domain names without relying on traditional centralized DNS infrastructure.

## Prerequisites

- GNS3 installed (version 2.2 or higher recommended)
- Docker support in GNS3
- Basic understanding of networking concepts

## Implementation Steps

### 1. Build and Push the Docker Image

First, prepare the Docker image that will be used for all nodes in the network:

```bash
# Clone or create the project directory with all files
git clone <repository-url> # if available
cd decentralized-dns

# Build Docker image
docker build -t decentralized-dns:latest .

# Tag and push to Docker Hub (replace 'yourusername')
docker tag decentralized-dns:latest yourusername/decentralized-dns:latest
docker push yourusername/decentralized-dns:latest
```

### 2. Set Up GNS3 Topology

1. **Import Docker Image to GNS3**:

   - Open GNS3 → Edit → Preferences → Docker → New
   - Image name: `yourusername/decentralized-dns:latest`
   - Container name: `decentralized-dns`
   - Configure at least 1 network adapter

2. **Create the Network Topology**:

   Create the following components:

   - 1 Internet Router (optional for external connectivity)
   - 1 Core Switch
   - 4 Routers (Router1-4)
   - 4 LAN Switches (Switch1-4)
   - 8 Docker containers using your image:
     - 3 as Blockchain nodes
     - 2 as Validator nodes
     - 3 as Client nodes

3. **Connect Devices According to Topology**:

   ```
                      Internet Router
                            |
                       Core Switch
         ___________________|___________________
        |           |           |              |
    Router1      Router2     Router3        Router4
        |           |           |              |
   LAN Switch1  LAN Switch2  LAN Switch3   LAN Switch4
    ___|___      ___|___      ___|___       ___|___
   |       |    |       |    |       |     |       |
   Node1   Node2 Node3  Node4 Node5  Node6  Node7  Node8
   (BC)    (BC)  (BC)   (Val) (Val) (Client) (Client) (Client)
   ```

4. **Configure Routers and Switches**:
   - Configure router interfaces
   - Set up VLANs if needed
   - Establish routing between different subnets
   - Enable communications between all nodes

### 3. Node Configuration

#### IP Assignment Plan:

| Node Type  | Node Name    | IP Address   |
| ---------- | ------------ | ------------ |
| Blockchain | blockchain_1 | 192.168.1.10 |
| Blockchain | blockchain_2 | 192.168.1.11 |
| Blockchain | blockchain_3 | 192.168.1.12 |
| Validator  | validator_1  | 192.168.1.20 |
| Validator  | validator_2  | 192.168.1.21 |
| Client     | client_1     | 192.168.1.30 |
| Client     | client_2     | 192.168.1.31 |
| Client     | client_3     | 192.168.1.32 |

#### Blockchain Node Startup

Connect to the console of each blockchain node container and run:

```bash
# Set IP address and start the node
./start_node.sh blockchain blockchain_1 5000 192.168.1.10
```

Repeat for other blockchain nodes, changing the ID and IP address.

#### Validator Node Startup

Connect to the console of each validator node container and run:

```bash
# Set IP address and start the validator node
./start_node.sh validator validator_1 5000 192.168.1.20
```

Repeat for other validator nodes.

#### Client Node Startup

Connect to the console of each client node container and run:

```bash
# Set IP address and start the client
./start_node.sh client client_1 5000 192.168.1.30
```

### 4. Verify Network Connectivity

After starting all nodes, verify they can communicate with each other:

1. **Test network connectivity**:

   ```bash
   # From any node
   ping 192.168.1.10
   ping 192.168.1.20
   ```

2. **Check blockchain node status**:
   ```bash
   # On a client node
   curl http://192.168.1.10:5000/node/status
   ```

### 5. Using the DNS System

#### Domain Registration

On a client node:

```
dns> register example.com 192.168.1.100
```

#### Domain Resolution

On any client node:

```
dns> resolve example.com
```

#### Domain Update

On the owner client:

```
dns> update example.com 192.168.1.101
```

#### Domain Transfer

On the owner client:

```
dns> transfer example.com client_2
```

#### List All Domains

On any client:

```
dns> list_records
```

### 6. Testing Network Resilience

To demonstrate the decentralized nature of the system:

1. **Test Continued Operation**:

   - Stop one blockchain node
   - Verify DNS operations still work
   - Stop a validator node
   - Verify blockchain still validates transactions
   - Restart nodes and verify data consistency

2. **Verify Data Propagation**:
   - Register a domain on one client
   - Verify it appears in list_records on another client
   - Update a domain and verify the change propagates

### 7. Troubleshooting

#### Network Connectivity Issues

If nodes can't connect:

```bash
# Check interface status
ip addr show

# Check routing
ip route

# Test connectivity
ping 192.168.1.10
```

#### Node Connection Issues

If blockchain nodes can't find each other:

```bash
# Manually connect nodes
curl -X POST -H "Content-Type: application/json" \
     -d '{"peer": "http://192.168.1.11:5000"}' \
     http://192.168.1.10:5000/peers/register
```

#### Domain Registration Failures

- Check if domain already exists
- Verify transaction reached a validator
- Check validator status

#### DNS Resolution Failures

- Check if domain exists
- Verify client is connected to blockchain nodes
- Check domain hasn't expired

## Project Flow Summary

1. **Network Initialization**:

   - Blockchain nodes start and establish genesis blocks
   - Validator nodes connect and register with blockchain nodes
   - All nodes form a peer-to-peer network

2. **Domain Management**:

   - Clients connect to blockchain nodes
   - Domains are registered, updated, transferred via transactions
   - Validator nodes validate and create blocks with transactions
   - Blockchain maintains consensus on DNS records

3. **DNS Resolution**:
   - Clients query blockchain for domain resolution
   - Results are cached locally for improved performance
   - Cache expires and refreshes from blockchain

## Conclusion

This decentralized DNS system demonstrates how blockchain technology can provide:

1. **Censorship Resistance**: No central authority controls domain registrations
2. **Increased Security**: Cryptographic verification of ownership
3. **Fault Tolerance**: System works even if some nodes fail
4. **Transparency**: All changes recorded immutably on blockchain

The implementation in GNS3 showcases how this technology could be deployed in real-world networking environments.
