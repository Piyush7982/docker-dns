// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DecentralizedDNS {
    struct DomainRecord {
        address owner;
        string ipAddress;
        uint256 creationTime;
        uint256 expirationTime;
        bool isActive;
    }
    
    // Domain name to record mapping
    mapping(string => DomainRecord) public domains;
    
    // Domain names owned by an address
    mapping(address => string[]) public ownedDomains;
    
    // Events
    event DomainRegistered(string domainName, string ipAddress, address owner);
    event DomainTransferred(string domainName, address previousOwner, address newOwner);
    event DomainUpdated(string domainName, string newIpAddress);
    event DomainRenewed(string domainName, uint256 newExpirationTime);
    
    // Domain registration fee in wei
    uint256 public registrationFee = 0.01 ether;
    
    // Default registration period in seconds (1 year)
    uint256 public defaultRegistrationPeriod = 365 days;
    
    // Contract owner
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner can call this function");
        _;
    }
    
    modifier onlyDomainOwner(string memory domainName) {
        require(domains[domainName].owner == msg.sender, "Only domain owner can call this function");
        _;
    }
    
    function registerDomain(string memory domainName, string memory ipAddress) public payable {
        // Check if domain already exists and is active
        require(!domains[domainName].isActive, "Domain already registered");
        
        // Check if registration fee is paid
        require(msg.value >= registrationFee, "Insufficient registration fee");
        
        // Create a new domain record
        DomainRecord memory newDomain = DomainRecord({
            owner: msg.sender,
            ipAddress: ipAddress,
            creationTime: block.timestamp,
            expirationTime: block.timestamp + defaultRegistrationPeriod,
            isActive: true
        });
        
        // Store the domain record
        domains[domainName] = newDomain;
        
        // Add domain to owner's list
        ownedDomains[msg.sender].push(domainName);
        
        // Emit event
        emit DomainRegistered(domainName, ipAddress, msg.sender);
    }
    
    function updateDomainIP(string memory domainName, string memory newIpAddress) public onlyDomainOwner(domainName) {
        require(domains[domainName].isActive, "Domain is not active");
        
        domains[domainName].ipAddress = newIpAddress;
        
        emit DomainUpdated(domainName, newIpAddress);
    }
    
    function transferDomain(string memory domainName, address newOwner) public onlyDomainOwner(domainName) {
        require(domains[domainName].isActive, "Domain is not active");
        require(newOwner != address(0), "Cannot transfer to zero address");
        
        address previousOwner = domains[domainName].owner;
        domains[domainName].owner = newOwner;
        
        // Add domain to new owner's list
        ownedDomains[newOwner].push(domainName);
        
        // Remove domain from previous owner's list (simplified - not efficient)
        // In a production environment, you'd want a more gas-efficient approach
        
        emit DomainTransferred(domainName, previousOwner, newOwner);
    }
    
    function renewDomain(string memory domainName) public payable onlyDomainOwner(domainName) {
        require(domains[domainName].isActive, "Domain is not active");
        require(msg.value >= registrationFee, "Insufficient renewal fee");
        
        domains[domainName].expirationTime += defaultRegistrationPeriod;
        
        emit DomainRenewed(domainName, domains[domainName].expirationTime);
    }
    
    function resolveDomain(string memory domainName) public view returns (string memory) {
        require(domains[domainName].isActive, "Domain is not active or does not exist");
        require(block.timestamp < domains[domainName].expirationTime, "Domain has expired");
        
        return domains[domainName].ipAddress;
    }
    
    function getDomainInfo(string memory domainName) public view returns (
        address domainOwner,
        string memory ipAddress,
        uint256 creationTime,
        uint256 expirationTime,
        bool isActive
    ) {
        DomainRecord memory domain = domains[domainName];
        return (
            domain.owner,
            domain.ipAddress,
            domain.creationTime,
            domain.expirationTime,
            domain.isActive
        );
    }
    
    function getOwnedDomains(address domainOwner) public view returns (string[] memory) {
        return ownedDomains[domainOwner];
    }
    
    function setRegistrationFee(uint256 newFee) public onlyOwner {
        registrationFee = newFee;
    }
    
    function withdrawFees() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
} 