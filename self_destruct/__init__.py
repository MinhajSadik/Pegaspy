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
    WipeResult,
    SecureDelete
)

from .evidence_eliminator import (
    EvidenceEliminator,
    EvidenceType,
    EliminationMethod,
    EvidenceTarget,
    EliminationResult
)

from .trigger_manager import (
    TriggerManager,
    TriggerType,
    TriggerEvent,
    TriggerCondition as TriggerCond,
    TriggerAction
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
    'WipeResult',
    'SecureDelete',
    'EvidenceEliminator',
    'EvidenceType',
    'EliminationMethod',
    'EvidenceTarget',
    'EliminationResult',
    'TriggerManager',
    'TriggerType',
    'TriggerEvent',
    'TriggerCond',
    'TriggerAction'
]

__version__ = "1.0.0"
__author__ = "PegaSpy Development Team"
__description__ = "Advanced self-destruct capabilities for PegaSpy framework"