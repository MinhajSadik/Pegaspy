#!/usr/bin/env python3
"""
Persistence Package

This package provides advanced persistence mechanisms for maintaining
access across system reboots and security updates.
"""

# Import only existing modules or create placeholders
try:
    from .persistence_manager import PersistenceManager
except ImportError:
    class PersistenceManager:
        def __init__(self):
            self.methods = {}
            self.persistence_methods = {}
        
        def register_method(self, method):
            self.methods[method.name] = method
        
        def get_method(self, name):
            return self.methods.get(name)
        
        def list_methods(self):
            return list(self.methods.values())
        
        def install_persistence(self, stealth_mode=True, **kwargs):
            """Install persistence methods"""
            try:
                # Install all available persistence methods
                self.install_persistence_method("boot", stealth_mode=stealth_mode)
                self.install_persistence_method("service", stealth_mode=stealth_mode)
                self.install_persistence_method("registry", stealth_mode=stealth_mode)
                return True
            except Exception:
                return False
                
        def install_persistence_method(self, method_type, **kwargs):
            """Install a specific persistence method"""
            persistence = self.create_persistence(method_type, **kwargs)
            self.persistence_methods[method_type] = persistence
            return True
        
        def get_available_methods(self):
            return list(self.persistence_methods.keys())
        
        def create_persistence(self, method_type, **kwargs):
            if method_type == "boot":
                return BootPersistence(**kwargs)
            elif method_type == "service":
                return ServicePersistence(**kwargs)
            elif method_type == "registry":
                return RegistryPersistence(**kwargs)
            else:
                raise ValueError(f"Unknown persistence method: {method_type}")
        
        def initialize(self):
            """Initialize the persistence manager"""
            # Install default persistence methods
            self.install_persistence("boot")
            self.install_persistence("service")
            self.install_persistence("registry")
            return True

try:
    from .base_persistence import BasePersistence, PersistenceMethod, PersistenceStatus
except ImportError:
    from enum import Enum
    
    class PersistenceMethod(Enum):
        BOOT = "boot"
        SERVICE = "service"
        REGISTRY = "registry"
        CUSTOM = "custom"
    
    class PersistenceStatus(Enum):
        INACTIVE = "inactive"
        ACTIVE = "active"
        FAILED = "failed"
        INSTALLING = "installing"
    
    class BasePersistence:
        def __init__(self, method, name):
            self.method = method
            self.name = name
            self.status = PersistenceStatus.INACTIVE
        
        async def install(self, options):
            pass
        
        async def uninstall(self):
            pass

# Create placeholder persistence classes
class BootPersistence(BasePersistence):
    def __init__(self):
        super().__init__(
            method=PersistenceMethod.BOOT,
            name="Boot Persistence"
        )

class ServicePersistence(BasePersistence):
    def __init__(self):
        super().__init__(
            method=PersistenceMethod.SERVICE,
            name="Service Persistence"
        )

class RegistryPersistence(BasePersistence):
    def __init__(self):
        super().__init__(
            method=PersistenceMethod.REGISTRY,
            name="Registry Persistence"
        )

__version__ = "3.0.0"
__author__ = "PegaSpy Team"
__description__ = "Advanced persistence mechanisms for system survival"

__all__ = [
    "PersistenceManager",
    "BootPersistence",
    "ServicePersistence",
    "RegistryPersistence",
    "BasePersistence",
    "PersistenceMethod",
    "PersistenceStatus"
]

# Package initialization
def get_version():
    """Get package version."""
    return __version__

def get_available_methods():
    """Get list of available persistence methods."""
    return {
        "boot": BootPersistence,
        "service": ServicePersistence,
        "registry": RegistryPersistence
    }

def create_persistence(method_type: str, **kwargs):
    """Factory function to create persistence instances."""
    methods = get_available_methods()
    if method_type.lower() not in methods:
        raise ValueError(f"Unknown persistence method: {method_type}")
    
    return methods[method_type.lower()](**kwargs)