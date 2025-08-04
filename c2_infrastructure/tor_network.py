#!/usr/bin/env python3
"""
PegaSpy C2 Infrastructure - Tor Network Manager
Provides anonymized communication through Tor network with advanced obfuscation.
"""

import asyncio
import json
import logging
import random
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
import hashlib
import base64
from datetime import datetime, timedelta

class TorNodeType(Enum):
    """Types of Tor nodes in the network."""
    ENTRY = "entry"
    MIDDLE = "middle"
    EXIT = "exit"
    BRIDGE = "bridge"
    HIDDEN_SERVICE = "hidden_service"

class ConnectionStatus(Enum):
    """Status of Tor connections."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    FAILED = "failed"
    BURNED = "burned"

@dataclass
class TorNode:
    """Represents a Tor node in the network."""
    node_id: str
    node_type: TorNodeType
    ip_address: str
    port: int
    fingerprint: str
    bandwidth: int = 0
    uptime: float = 0.0
    last_seen: datetime = field(default_factory=datetime.now)
    is_stable: bool = True
    is_fast: bool = True
    country_code: str = "US"
    exit_policy: List[str] = field(default_factory=list)
    contact_info: str = ""
    version: str = "0.4.7.10"
    
    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = self._generate_fingerprint()
    
    def _generate_fingerprint(self) -> str:
        """Generate a realistic Tor node fingerprint."""
        data = f"{self.ip_address}:{self.port}:{self.node_id}"
        return hashlib.sha1(data.encode()).hexdigest().upper()

@dataclass
class TorCircuit:
    """Represents a Tor circuit path."""
    circuit_id: str
    nodes: List[TorNode]
    created_at: datetime = field(default_factory=datetime.now)
    status: ConnectionStatus = ConnectionStatus.DISCONNECTED
    bandwidth_used: int = 0
    last_activity: datetime = field(default_factory=datetime.now)
    is_internal: bool = False
    purpose: str = "general"
    
    @property
    def path_length(self) -> int:
        return len(self.nodes)
    
    @property
    def is_expired(self) -> bool:
        """Check if circuit has expired (10 minutes default)."""
        return datetime.now() - self.created_at > timedelta(minutes=10)

@dataclass
class HiddenService:
    """Represents a Tor hidden service."""
    service_id: str
    onion_address: str
    private_key: str
    public_key: str
    port_mappings: Dict[int, int] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    is_active: bool = False
    client_auth: bool = False
    authorized_clients: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.onion_address:
            self.onion_address = self._generate_onion_address()
    
    def _generate_onion_address(self) -> str:
        """Generate a realistic v3 onion address."""
        # Simulate v3 onion address generation
        random_bytes = random.randbytes(32)
        encoded = base64.b32encode(random_bytes).decode().lower().rstrip('=')
        return f"{encoded[:56]}.onion"

class TorNetworkManager:
    """Manages Tor network connections and circuits for C2 infrastructure."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.logger = logging.getLogger(__name__)
        
        # Network state
        self.available_nodes: Dict[str, TorNode] = {}
        self.active_circuits: Dict[str, TorCircuit] = {}
        self.hidden_services: Dict[str, HiddenService] = {}
        self.burned_nodes: set = set()
        
        # Connection management
        self.control_socket = None
        self.is_connected = False
        self.last_consensus_update = datetime.now()
        
        # Statistics
        self.stats = {
            'circuits_created': 0,
            'circuits_failed': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'nodes_burned': 0,
            'hidden_services_created': 0
        }
        
        # Initialize with some realistic nodes
        self._initialize_node_database()
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for Tor network manager."""
        return {
            'control_port': 9051,
            'socks_port': 9050,
            'control_password': None,
            'circuit_timeout': 600,  # 10 minutes
            'max_circuits': 50,
            'min_circuit_length': 3,
            'max_circuit_length': 5,
            'bridge_mode': False,
            'use_guards': True,
            'strict_nodes': False,
            'exclude_countries': ['CN', 'RU', 'IR'],
            'preferred_countries': ['US', 'DE', 'NL', 'SE'],
            'bandwidth_threshold': 1024 * 1024,  # 1 MB/s
            'consensus_update_interval': 3600,  # 1 hour
            'circuit_rotation_interval': 300,  # 5 minutes
            'hidden_service_rotation': 86400,  # 24 hours
        }
    
    def _initialize_node_database(self):
        """Initialize with realistic Tor node data."""
        # Simulate real Tor network nodes
        sample_nodes = [
            {
                'node_id': 'guard_001',
                'type': TorNodeType.ENTRY,
                'ip': '185.220.101.32',
                'port': 443,
                'country': 'DE',
                'bandwidth': 10 * 1024 * 1024,
                'uptime': 0.99
            },
            {
                'node_id': 'middle_001',
                'type': TorNodeType.MIDDLE,
                'ip': '199.87.154.255',
                'port': 9001,
                'country': 'US',
                'bandwidth': 50 * 1024 * 1024,
                'uptime': 0.95
            },
            {
                'node_id': 'exit_001',
                'type': TorNodeType.EXIT,
                'ip': '185.220.102.8',
                'port': 9001,
                'country': 'NL',
                'bandwidth': 20 * 1024 * 1024,
                'uptime': 0.97
            },
            {
                'node_id': 'bridge_001',
                'type': TorNodeType.BRIDGE,
                'ip': '192.95.36.142',
                'port': 443,
                'country': 'CA',
                'bandwidth': 5 * 1024 * 1024,
                'uptime': 0.92
            }
        ]
        
        for node_data in sample_nodes:
            node = TorNode(
                node_id=node_data['node_id'],
                node_type=node_data['type'],
                ip_address=node_data['ip'],
                port=node_data['port'],
                fingerprint='',
                bandwidth=node_data['bandwidth'],
                uptime=node_data['uptime'],
                country_code=node_data['country'],
                is_stable=node_data['uptime'] > 0.9,
                is_fast=node_data['bandwidth'] > self.config['bandwidth_threshold']
            )
            self.available_nodes[node.node_id] = node
    
    async def initialize(self) -> bool:
        """Initialize Tor network connection."""
        try:
            self.logger.info("Initializing Tor network manager...")
            
            # Simulate Tor control connection
            await self._connect_to_control_port()
            
            # Update consensus
            await self._update_consensus()
            
            # Create initial circuits
            await self._create_initial_circuits()
            
            self.is_connected = True
            self.logger.info("Tor network manager initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Tor network: {e}")
            return False
    
    async def _connect_to_control_port(self):
        """Connect to Tor control port."""
        # Simulate control port connection
        await asyncio.sleep(0.1)
        self.logger.info(f"Connected to Tor control port {self.config['control_port']}")
    
    async def _update_consensus(self):
        """Update Tor network consensus."""
        self.logger.info("Updating Tor network consensus...")
        
        # Simulate consensus update
        await asyncio.sleep(0.5)
        
        # Add some random nodes to simulate real network
        for i in range(random.randint(5, 15)):
            node_id = f"node_{random.randint(1000, 9999)}"
            if node_id not in self.available_nodes:
                node = TorNode(
                    node_id=node_id,
                    node_type=random.choice(list(TorNodeType)),
                    ip_address=f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    port=random.choice([443, 9001, 9030, 9050]),
                    fingerprint='',
                    bandwidth=random.randint(1024*1024, 100*1024*1024),
                    uptime=random.uniform(0.8, 0.99),
                    country_code=random.choice(['US', 'DE', 'NL', 'SE', 'FR', 'UK'])
                )
                self.available_nodes[node_id] = node
        
        self.last_consensus_update = datetime.now()
        self.logger.info(f"Consensus updated. {len(self.available_nodes)} nodes available")
    
    async def _create_initial_circuits(self):
        """Create initial circuits for C2 communication."""
        initial_circuits = min(5, self.config['max_circuits'])
        
        for i in range(initial_circuits):
            circuit = await self.create_circuit(purpose=f"initial_{i}")
            if circuit:
                self.logger.info(f"Created initial circuit: {circuit.circuit_id}")
    
    async def create_circuit(self, purpose: str = "general", 
                           path_length: Optional[int] = None) -> Optional[TorCircuit]:
        """Create a new Tor circuit."""
        try:
            if len(self.active_circuits) >= self.config['max_circuits']:
                await self._cleanup_expired_circuits()
            
            if not path_length:
                path_length = random.randint(
                    self.config['min_circuit_length'],
                    self.config['max_circuit_length']
                )
            
            # Select nodes for circuit path
            circuit_nodes = await self._select_circuit_path(path_length)
            if not circuit_nodes:
                self.logger.warning("Failed to select circuit path")
                return None
            
            circuit_id = f"circuit_{int(time.time())}_{random.randint(1000, 9999)}"
            circuit = TorCircuit(
                circuit_id=circuit_id,
                nodes=circuit_nodes,
                purpose=purpose,
                status=ConnectionStatus.CONNECTING
            )
            
            # Simulate circuit creation
            await self._build_circuit(circuit)
            
            if circuit.status == ConnectionStatus.CONNECTED:
                self.active_circuits[circuit_id] = circuit
                self.stats['circuits_created'] += 1
                self.logger.info(f"Circuit {circuit_id} created successfully")
                return circuit
            else:
                self.stats['circuits_failed'] += 1
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to create circuit: {e}")
            self.stats['circuits_failed'] += 1
            return None
    
    async def _select_circuit_path(self, path_length: int) -> List[TorNode]:
        """Select optimal nodes for circuit path."""
        available = [node for node in self.available_nodes.values() 
                    if node.node_id not in self.burned_nodes]
        
        if len(available) < path_length:
            self.logger.warning("Not enough available nodes for circuit")
            return []
        
        # Filter by country preferences
        preferred_nodes = [node for node in available 
                          if node.country_code in self.config['preferred_countries']]
        
        excluded_nodes = [node for node in available 
                         if node.country_code in self.config['exclude_countries']]
        
        # Remove excluded nodes
        available = [node for node in available if node not in excluded_nodes]
        
        if len(available) < path_length:
            self.logger.warning("Not enough nodes after filtering")
            return []
        
        # Select path ensuring diversity
        selected_nodes = []
        used_countries = set()
        used_ips = set()
        
        # Prefer high-bandwidth, stable nodes
        available.sort(key=lambda x: (x.is_stable, x.is_fast, x.bandwidth), reverse=True)
        
        for node in available:
            if len(selected_nodes) >= path_length:
                break
            
            # Ensure diversity
            if (node.country_code not in used_countries and 
                node.ip_address.split('.')[0] not in used_ips):
                selected_nodes.append(node)
                used_countries.add(node.country_code)
                used_ips.add(node.ip_address.split('.')[0])
        
        # Fill remaining slots if needed
        while len(selected_nodes) < path_length and len(available) > len(selected_nodes):
            for node in available:
                if node not in selected_nodes:
                    selected_nodes.append(node)
                    break
        
        return selected_nodes[:path_length]
    
    async def _build_circuit(self, circuit: TorCircuit):
        """Build the circuit through selected nodes."""
        try:
            self.logger.info(f"Building circuit {circuit.circuit_id} through {len(circuit.nodes)} nodes")
            
            # Simulate circuit building with realistic delays
            for i, node in enumerate(circuit.nodes):
                await asyncio.sleep(random.uniform(0.1, 0.5))  # Simulate network delay
                
                # Simulate occasional failures
                if random.random() < 0.05:  # 5% failure rate
                    circuit.status = ConnectionStatus.FAILED
                    self.logger.warning(f"Circuit build failed at node {i+1}: {node.node_id}")
                    return
                
                self.logger.debug(f"Extended circuit to {node.node_id} ({node.ip_address})")
            
            circuit.status = ConnectionStatus.CONNECTED
            circuit.last_activity = datetime.now()
            
        except Exception as e:
            circuit.status = ConnectionStatus.FAILED
            self.logger.error(f"Circuit build error: {e}")
    
    async def create_hidden_service(self, ports: Dict[int, int], 
                                  client_auth: bool = False) -> Optional[HiddenService]:
        """Create a new hidden service."""
        try:
            service_id = f"hs_{int(time.time())}_{random.randint(1000, 9999)}"
            
            # Generate keys (simplified)
            private_key = base64.b64encode(random.randbytes(32)).decode()
            public_key = base64.b64encode(random.randbytes(32)).decode()
            
            hidden_service = HiddenService(
                service_id=service_id,
                onion_address='',  # Will be generated in __post_init__
                private_key=private_key,
                public_key=public_key,
                port_mappings=ports,
                client_auth=client_auth
            )
            
            # Simulate hidden service creation
            await asyncio.sleep(random.uniform(1.0, 3.0))
            
            hidden_service.is_active = True
            self.hidden_services[service_id] = hidden_service
            self.stats['hidden_services_created'] += 1
            
            self.logger.info(f"Hidden service created: {hidden_service.onion_address}")
            return hidden_service
            
        except Exception as e:
            self.logger.error(f"Failed to create hidden service: {e}")
            return None
    
    async def send_data(self, circuit_id: str, data: bytes, 
                       destination: str) -> bool:
        """Send data through a specific circuit."""
        try:
            if circuit_id not in self.active_circuits:
                self.logger.error(f"Circuit {circuit_id} not found")
                return False
            
            circuit = self.active_circuits[circuit_id]
            if circuit.status != ConnectionStatus.CONNECTED:
                self.logger.error(f"Circuit {circuit_id} not connected")
                return False
            
            # Simulate data transmission
            await asyncio.sleep(random.uniform(0.1, 0.5))
            
            # Update statistics
            self.stats['bytes_sent'] += len(data)
            circuit.bandwidth_used += len(data)
            circuit.last_activity = datetime.now()
            
            self.logger.debug(f"Sent {len(data)} bytes through circuit {circuit_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send data: {e}")
            return False
    
    async def receive_data(self, circuit_id: str, timeout: float = 30.0) -> Optional[bytes]:
        """Receive data from a specific circuit."""
        try:
            if circuit_id not in self.active_circuits:
                return None
            
            circuit = self.active_circuits[circuit_id]
            if circuit.status != ConnectionStatus.CONNECTED:
                return None
            
            # Simulate data reception
            await asyncio.sleep(random.uniform(0.1, 1.0))
            
            # Generate some fake response data
            response_data = json.dumps({
                'status': 'success',
                'timestamp': datetime.now().isoformat(),
                'circuit_id': circuit_id,
                'data': base64.b64encode(random.randbytes(random.randint(100, 1000))).decode()
            }).encode()
            
            self.stats['bytes_received'] += len(response_data)
            circuit.last_activity = datetime.now()
            
            return response_data
            
        except Exception as e:
            self.logger.error(f"Failed to receive data: {e}")
            return None
    
    async def burn_circuit(self, circuit_id: str, burn_nodes: bool = False):
        """Burn a circuit and optionally its nodes."""
        try:
            if circuit_id not in self.active_circuits:
                return
            
            circuit = self.active_circuits[circuit_id]
            
            if burn_nodes:
                for node in circuit.nodes:
                    self.burned_nodes.add(node.node_id)
                    self.stats['nodes_burned'] += 1
                    self.logger.warning(f"Burned node: {node.node_id}")
            
            circuit.status = ConnectionStatus.BURNED
            del self.active_circuits[circuit_id]
            
            self.logger.info(f"Burned circuit: {circuit_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to burn circuit: {e}")
    
    async def rotate_circuits(self):
        """Rotate all active circuits for security."""
        try:
            self.logger.info("Rotating all circuits...")
            
            old_circuits = list(self.active_circuits.keys())
            new_circuits = []
            
            # Create new circuits
            for old_circuit_id in old_circuits:
                old_circuit = self.active_circuits[old_circuit_id]
                new_circuit = await self.create_circuit(purpose=old_circuit.purpose)
                if new_circuit:
                    new_circuits.append(new_circuit.circuit_id)
            
            # Burn old circuits
            for old_circuit_id in old_circuits:
                await self.burn_circuit(old_circuit_id)
            
            self.logger.info(f"Circuit rotation complete. {len(new_circuits)} new circuits created")
            
        except Exception as e:
            self.logger.error(f"Circuit rotation failed: {e}")
    
    async def _cleanup_expired_circuits(self):
        """Clean up expired circuits."""
        expired_circuits = []
        
        for circuit_id, circuit in self.active_circuits.items():
            if circuit.is_expired or circuit.status == ConnectionStatus.FAILED:
                expired_circuits.append(circuit_id)
        
        for circuit_id in expired_circuits:
            await self.burn_circuit(circuit_id)
        
        if expired_circuits:
            self.logger.info(f"Cleaned up {len(expired_circuits)} expired circuits")
    
    def get_network_status(self) -> Dict[str, Any]:
        """Get current network status."""
        active_circuits = len(self.active_circuits)
        available_nodes = len([n for n in self.available_nodes.values() 
                              if n.node_id not in self.burned_nodes])
        
        return {
            'connected': self.is_connected,
            'active_circuits': active_circuits,
            'available_nodes': available_nodes,
            'burned_nodes': len(self.burned_nodes),
            'hidden_services': len(self.hidden_services),
            'last_consensus_update': self.last_consensus_update.isoformat(),
            'statistics': self.stats.copy(),
            'circuit_details': [
                {
                    'id': circuit.circuit_id,
                    'status': circuit.status.value,
                    'path_length': circuit.path_length,
                    'bandwidth_used': circuit.bandwidth_used,
                    'age_minutes': (datetime.now() - circuit.created_at).total_seconds() / 60,
                    'purpose': circuit.purpose
                }
                for circuit in self.active_circuits.values()
            ]
        }
    
    async def emergency_burn_all(self):
        """Emergency function to burn all circuits and nodes."""
        self.logger.critical("EMERGENCY BURN ACTIVATED - Destroying all circuits and nodes")
        
        # Burn all circuits
        for circuit_id in list(self.active_circuits.keys()):
            await self.burn_circuit(circuit_id, burn_nodes=True)
        
        # Burn all hidden services
        for service_id in list(self.hidden_services.keys()):
            del self.hidden_services[service_id]
        
        # Mark all nodes as burned
        for node_id in self.available_nodes.keys():
            self.burned_nodes.add(node_id)
        
        self.is_connected = False
        self.logger.critical("Emergency burn complete - All assets destroyed")
    
    async def shutdown(self):
        """Gracefully shutdown the Tor network manager."""
        try:
            self.logger.info("Shutting down Tor network manager...")
            
            # Close all circuits
            for circuit_id in list(self.active_circuits.keys()):
                await self.burn_circuit(circuit_id)
            
            # Deactivate hidden services
            for service in self.hidden_services.values():
                service.is_active = False
            
            self.is_connected = False
            self.logger.info("Tor network manager shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")

# Example usage and testing
if __name__ == "__main__":
    async def test_tor_network():
        """Test the Tor network manager."""
        logging.basicConfig(level=logging.INFO)
        
        # Initialize manager
        tor_manager = TorNetworkManager()
        
        # Initialize network
        success = await tor_manager.initialize()
        if not success:
            print("Failed to initialize Tor network")
            return
        
        # Create some circuits
        print("\nCreating circuits...")
        for i in range(3):
            circuit = await tor_manager.create_circuit(purpose=f"test_{i}")
            if circuit:
                print(f"Created circuit: {circuit.circuit_id}")
        
        # Create hidden service
        print("\nCreating hidden service...")
        hidden_service = await tor_manager.create_hidden_service(
            ports={80: 8080, 443: 8443},
            client_auth=True
        )
        if hidden_service:
            print(f"Hidden service: {hidden_service.onion_address}")
        
        # Send some data
        print("\nTesting data transmission...")
        circuits = list(tor_manager.active_circuits.keys())
        if circuits:
            test_data = b"Hello, Tor network!"
            success = await tor_manager.send_data(
                circuits[0], test_data, "example.com"
            )
            print(f"Data sent: {success}")
            
            response = await tor_manager.receive_data(circuits[0])
            if response:
                print(f"Received {len(response)} bytes")
        
        # Show network status
        print("\nNetwork Status:")
        status = tor_manager.get_network_status()
        print(json.dumps(status, indent=2, default=str))
        
        # Test circuit rotation
        print("\nRotating circuits...")
        await tor_manager.rotate_circuits()
        
        # Final status
        print("\nFinal Network Status:")
        status = tor_manager.get_network_status()
        print(f"Active circuits: {status['active_circuits']}")
        print(f"Available nodes: {status['available_nodes']}")
        
        # Shutdown
        await tor_manager.shutdown()
        print("\nTor network manager test complete")
    
    # Run the test
    asyncio.run(test_tor_network())