"""Prevention & Hardening Tools Module

This module provides comprehensive system hardening and real-time protection
tools to prevent spyware infections and strengthen device security.

Components:
- System Hardening Suite: Configuration management and security controls
- Real-time Protection: Active threat prevention and monitoring
- Security Policy Engine: Automated security policy enforcement
- Network Protection: VPN integration and traffic filtering
"""

__version__ = "1.0.0"
__author__ = "PegaSpy Security Team"
__description__ = "Prevention & Hardening Tools for Anti-Spyware Defense"

# Import main components
from .system_hardening import SystemHardeningManager
from .app_permissions import AppPermissionManager
from .network_security import NetworkSecurityMonitor
from .realtime_protection import RealTimeProtectionEngine
from .exploit_detection import ZeroClickExploitDetector
from .link_scanner import MaliciousLinkScanner
from .app_integrity import AppIntegrityVerifier

__all__ = [
    'SystemHardeningManager',
    'AppPermissionManager', 
    'NetworkSecurityMonitor',
    'RealTimeProtectionEngine',
    'ZeroClickExploitDetector',
    'MaliciousLinkScanner',
    'AppIntegrityVerifier'
]