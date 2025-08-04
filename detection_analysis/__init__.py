"""Detection and Analysis Tools Module

This module contains tools for detecting and analyzing potential spyware threats:
- Mobile Device Scanner
- Network Traffic Analyzer
- File System Integrity Checker
- Behavioral Analysis Engine
"""

__version__ = "1.0.0"
__author__ = "PegaSpy Security Team"

from .mobile_scanner import MobileDeviceScanner
from .network_analyzer import NetworkTrafficAnalyzer
from .file_integrity import FileIntegrityChecker
from .behavioral_engine import BehavioralAnalysisEngine

__all__ = [
    "MobileDeviceScanner",
    "NetworkTrafficAnalyzer", 
    "FileIntegrityChecker",
    "BehavioralAnalysisEngine"
]