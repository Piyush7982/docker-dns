# Decentralized DNS on Blockchain for GNS3

This project implements a decentralized Domain Name System (DNS) using blockchain technology for deployment in GNS3. It allows users to register domain names, update DNS records, transfer domain ownership, and resolve domain names in a decentralized manner without relying on traditional centralized DNS infrastructure.

## Features

- Blockchain-based domain name registration and management
- Decentralized peer-to-peer network of blockchain nodes
- Proof of Authority (PoA) consensus mechanism
- Domain registration, renewal, transfer, and IP updates
- Client-side DNS resolution with local caching
- Smart contract for domain ownership and management

## Components

1. **Blockchain Nodes**: Regular nodes that store the blockchain data
2. **Validator Nodes**: Special nodes that validate and create new blocks
3. **Client Nodes**: End-user nodes that interact with the blockchain to register and resolve DNS records

## Network Topology

The recommended network topology in GNS3:

```
                     Internet Router
                           |
                     Core Switch
        ___________________|___________________
       |           |           |              |
   Router1      Router2     Router3        Router4
       |           |           |              |
  LAN Switch1  LAN Switch2  LAN Switch3   LAN Switch4
  ___|___       __|__       __|__         ___|___
 |       |     |     |     |     |       |       |
Node1   Node2 Node3 Node4 Node5 Node6   Node7   Node8
(BC)    (BC)  (BC)  (Val) (Val) (Client) (Client) (Client)

BC = Blockchain Node
Val = Validator Node
```

## Files Included

- `blockchain_node.py`: Implementation of blockchain nodes (regular and validator)
- `dns_client.py`: Client for interacting with the blockchain DNS system
- `dns_contract.sol`: Solidity smart contract for DNS on Ethereum (for reference)
- `deploy_contract.py`: Script to deploy the smart contract
- `requirements.txt`: Python package dependencies
- `Dockerfile`: For building the Docker image
- `start_node.sh`: Script to start different types of nodes
- `setup_network.sh`: Script to set up a test network

## Setup Instructions for GNS3

### Prerequisites

- GNS3 installed with Docker support
- Ubuntu Docker container set up in GNS3

### Steps

1. **Build the Docker Image**

```bash
docker build -t decentralized-dns:latest .
docker tag decentralized-dns:latest yourusername/decentralized-dns:latest
docker push yourusername/decentralized-dns:latest
```

2. **Setting up in GNS3**

   - Import the Docker image from Docker Hub into GNS3
   - Create the network topology as shown above
   - Assign IP addresses to all nodes

3. **Starting the Nodes**

   For a blockchain node:

   ```bash
   python3 blockchain_node.py --id blockchain_1 --port 5000
   ```

   For a validator node:

   ```bash
   python3 blockchain_node.py --id validator_1 --port 5001 --validator
   ```

   For a client node:

   ```bash
   python3 dns_client.py --nodes http://blockchain_node_ip:5000 --id client_1
   ```

   Or use the start script:

   ```bash
   ./start_node.sh blockchain blockchain_1 5000
   ./start_node.sh validator validator_1 5001
   ./start_node.sh client client_1 5002
   ```

4. **Quick Network Setup**

   To set up a test network with 3 blockchain nodes and 2 validator nodes:

   ```bash
   ./setup_network.sh
   ```

## Client Usage

Once a client is connected to the blockchain, you can use the following commands:

- Register a domain: `register example.com 192.168.1.10`
- Update a domain's IP: `update example.com 192.168.1.20`
- Transfer domain ownership: `transfer example.com new_owner_id`
- Renew a domain: `renew example.com`
- Resolve a domain: `resolve example.com`
- List all DNS records: `list_records`
- View node status: `node_status`
- Connect to another blockchain node: `connect http://node_ip:port`
- List connected nodes: `list_nodes`
- Show local DNS cache: `show_cache`
- Clear local DNS cache: `clear_cache`
- Exit the client: `exit`

## Project Workflow

1. Deploy blockchain and validator nodes
2. Create a peer-to-peer network by connecting all nodes
3. Clients connect to the blockchain and can register domains
4. Domain registrations, updates, and transfers are recorded on the blockchain
5. Clients can resolve domain names by querying the blockchain
6. Updates to the DNS records are propagated through the blockchain

## Why Decentralized DNS?

Traditional DNS systems are centralized, which creates a single point of failure and potential for censorship. A blockchain-based DNS offers:

1. **Censorship Resistance**: No central authority can take down or modify domain registrations
2. **Increased Security**: Uses blockchain's cryptographic security features
3. **Transparency**: All DNS registrations and changes are publicly visible on the blockchain
4. **Elimination of Central Points of Failure**: The system continues to work even if some nodes fail
5. **User Control**: Domain owners have complete control over their domains

## Limitations and Considerations

- Performance may be slower than traditional DNS due to blockchain validation
- Not directly compatible with existing DNS infrastructure without bridges
- Smart contract upgrades must be carefully managed
- Network requires a sufficient number of nodes for true decentralization

## Troubleshooting

- If nodes can't connect, check network configurations and firewall settings
- Ensure all nodes have unique IDs
- For domain registration failures, check if the domain already exists
- If transactions aren't being mined, verify that validator nodes are running correctly
