FROM ubuntu:20.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Update and install dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    git \
    curl \
    iputils-ping \
    net-tools \
    iproute2 \
    nano \
    wget \
    software-properties-common \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js and npm for Ethereum tools
RUN curl -sL https://deb.nodesource.com/setup_14.x | bash - \
    && apt-get install -y nodejs

# Install Solidity compiler
RUN add-apt-repository ppa:ethereum/ethereum \
    && apt-get update \
    && apt-get install -y solc

# Set up working directory
WORKDIR /app

# Copy project files
COPY . /app/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Make all scripts executable
RUN chmod +x *.py *.sh

# Expose ports for blockchain nodes and DNS services
EXPOSE 5000-5010

# Default command to show help text
CMD ["echo", "Decentralized DNS on Blockchain Container. Use './start_node.sh blockchain blockchain_1 5000 192.168.1.10' to start a blockchain node, './start_node.sh validator validator_1 5000 192.168.1.20' to start a validator node, or './start_node.sh client client_1 5000 192.168.1.30' to start a DNS client."]
