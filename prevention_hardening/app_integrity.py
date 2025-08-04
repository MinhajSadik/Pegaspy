"""App Integrity Verifier

Comprehensive application integrity monitoring and tamper detection:
- Binary signature verification
- Code signing validation
- Runtime integrity checks
- File system monitoring
- Memory protection analysis
- Anti-tampering mechanisms
"""

import os
import sys
import time
import json
import hashlib
import threading
import subprocess
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from collections import defaultdict, deque
from loguru import logger

try:
    import psutil
except ImportError:
    psutil = None

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
except ImportError:
    x509 = None
    hashes = None
    serialization = None
    rsa = None
    padding = None

try:
    import yara
except ImportError:
    yara = None


class IntegrityStatus(Enum):
    """Application integrity status"""
    VERIFIED = "verified"
    COMPROMISED = "compromised"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    ERROR = "error"


class TamperType(Enum):
    """Types of tampering detected"""
    CODE_INJECTION = "code_injection"
    BINARY_MODIFICATION = "binary_modification"
    SIGNATURE_INVALID = "signature_invalid"
    CERTIFICATE_REVOKED = "certificate_revoked"
    MEMORY_CORRUPTION = "memory_corruption"
    RUNTIME_PATCHING = "runtime_patching"
    LIBRARY_HIJACKING = "library_hijacking"
    PROCESS_HOLLOWING = "process_hollowing"
    DLL_INJECTION = "dll_injection"
    HOOK_INSTALLATION = "hook_installation"
    DEBUGGER_DETECTION = "debugger_detection"
    VIRTUALIZATION_EVASION = "virtualization_evasion"


class VerificationMethod(Enum):
    """Verification methods"""
    HASH_COMPARISON = "hash_comparison"
    DIGITAL_SIGNATURE = "digital_signature"
    CODE_SIGNING = "code_signing"
    CERTIFICATE_CHAIN = "certificate_chain"
    RUNTIME_ANALYSIS = "runtime_analysis"
    MEMORY_SCANNING = "memory_scanning"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    YARA_RULES = "yara_rules"


@dataclass
class AppSignature:
    """Application signature information"""
    app_path: str
    file_hash: str
    hash_algorithm: str
    file_size: int
    creation_time: str
    modification_time: str
    digital_signature: Optional[str]
    certificate_info: Optional[Dict[str, Any]]
    code_signing_valid: bool
    signature_timestamp: str
    

@dataclass
class IntegrityBaseline:
    """Application integrity baseline"""
    app_id: str
    app_name: str
    app_version: str
    app_path: str
    baseline_hash: str
    file_signatures: Dict[str, str]  # file_path -> hash
    memory_regions: Dict[str, str]  # region_name -> hash
    loaded_libraries: List[str]
    process_characteristics: Dict[str, Any]
    baseline_timestamp: str
    verification_methods: List[VerificationMethod]
    

@dataclass
class TamperDetection:
    """Tamper detection result"""
    tamper_type: TamperType
    severity: str  # low, medium, high, critical
    description: str
    affected_files: List[str]
    detection_method: VerificationMethod
    evidence: Dict[str, Any]
    confidence_score: float
    detection_timestamp: str
    

@dataclass
class IntegrityReport:
    """Comprehensive integrity verification report"""
    app_id: str
    app_name: str
    app_path: str
    verification_timestamp: str
    overall_status: IntegrityStatus
    integrity_score: float
    baseline_comparison: Dict[str, Any]
    tamper_detections: List[TamperDetection]
    signature_verification: Dict[str, Any]
    runtime_analysis: Dict[str, Any]
    recommendations: List[str]
    mitigation_actions: List[str]
    verification_duration: float
    

class AppIntegrityVerifier:
    """Advanced application integrity verification and tamper detection system"""
    
    def __init__(self):
        # Application baselines
        self.app_baselines: Dict[str, IntegrityBaseline] = {}
        
        # Known good signatures
        self.trusted_signatures: Set[str] = set()
        
        # Tamper detection rules
        self.tamper_rules: List[Dict[str, Any]] = []
        
        # Monitoring state
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.monitored_apps: Set[str] = set()
        
        # Detection statistics
        self.detection_stats = {
            'total_verifications': 0,
            'compromised_apps': 0,
            'suspicious_apps': 0,
            'tamper_detections': 0,
            'false_positives': 0
        }
        
        # YARA rules for tamper detection
        self.yara_rules = None
        
        # Initialize components
        self._initialize_tamper_rules()
        self._initialize_yara_rules()
        self._load_trusted_signatures()
        
        logger.info("AppIntegrityVerifier initialized")
    
    def _initialize_tamper_rules(self) -> None:
        """Initialize tamper detection rules"""
        self.tamper_rules = [
            {
                'name': 'Unexpected File Modification',
                'type': TamperType.BINARY_MODIFICATION,
                'pattern': 'hash_mismatch',
                'severity': 'high',
                'description': 'Application binary has been modified'
            },
            {
                'name': 'Invalid Digital Signature',
                'type': TamperType.SIGNATURE_INVALID,
                'pattern': 'signature_invalid',
                'severity': 'critical',
                'description': 'Digital signature verification failed'
            },
            {
                'name': 'Code Injection Detected',
                'type': TamperType.CODE_INJECTION,
                'pattern': 'memory_anomaly',
                'severity': 'critical',
                'description': 'Code injection detected in process memory'
            },
            {
                'name': 'Library Hijacking',
                'type': TamperType.LIBRARY_HIJACKING,
                'pattern': 'unexpected_library',
                'severity': 'high',
                'description': 'Unexpected library loaded by application'
            },
            {
                'name': 'Runtime Patching',
                'type': TamperType.RUNTIME_PATCHING,
                'pattern': 'runtime_modification',
                'severity': 'medium',
                'description': 'Runtime code modification detected'
            },
            {
                'name': 'Debugger Attachment',
                'type': TamperType.DEBUGGER_DETECTION,
                'pattern': 'debugger_present',
                'severity': 'medium',
                'description': 'Debugger attached to process'
            }
        ]
        
        logger.info(f"Loaded {len(self.tamper_rules)} tamper detection rules")
    
    def _initialize_yara_rules(self) -> None:
        """Initialize YARA rules for tamper detection"""
        if not yara:
            logger.warning("YARA not available - advanced detection disabled")
            return
        
        yara_rule_source = '''
        rule CodeInjection {
            meta:
                description = "Detects code injection patterns"
                severity = "high"
            strings:
                $inject1 = { 68 ?? ?? ?? ?? C3 }  // push addr; ret
                $inject2 = { E8 ?? ?? ?? ?? 83 C4 ?? }  // call; add esp
                $inject3 = { FF 25 ?? ?? ?? ?? }  // jmp dword ptr
            condition:
                any of them
        }
        
        rule ProcessHollowing {
            meta:
                description = "Detects process hollowing techniques"
                severity = "critical"
            strings:
                $hollow1 = "NtUnmapViewOfSection"
                $hollow2 = "VirtualAllocEx"
                $hollow3 = "WriteProcessMemory"
                $hollow4 = "SetThreadContext"
            condition:
                3 of them
        }
        
        rule DLLInjection {
            meta:
                description = "Detects DLL injection patterns"
                severity = "high"
            strings:
                $dll1 = "LoadLibraryA"
                $dll2 = "LoadLibraryW"
                $dll3 = "GetProcAddress"
                $dll4 = "VirtualAllocEx"
            condition:
                all of them
        }
        
        rule AntiDebug {
            meta:
                description = "Detects anti-debugging techniques"
                severity = "medium"
            strings:
                $debug1 = "IsDebuggerPresent"
                $debug2 = "CheckRemoteDebuggerPresent"
                $debug3 = "NtQueryInformationProcess"
                $debug4 = "OutputDebugStringA"
            condition:
                2 of them
        }
        '''
        
        try:
            self.yara_rules = yara.compile(source=yara_rule_source)
            logger.info("YARA rules compiled successfully")
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
    
    def _load_trusted_signatures(self) -> None:
        """Load trusted application signatures"""
        # In production, load from secure database or configuration
        trusted_apps = [
            # System applications
            '/System/Applications/Safari.app/Contents/MacOS/Safari',
            '/System/Applications/Mail.app/Contents/MacOS/Mail',
            '/System/Applications/Messages.app/Contents/MacOS/Messages',
            '/System/Applications/FaceTime.app/Contents/MacOS/FaceTime',
            
            # Common applications
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
            '/Applications/Firefox.app/Contents/MacOS/firefox',
            '/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word',
            '/Applications/Slack.app/Contents/MacOS/Slack',
            '/Applications/Zoom.app/Contents/MacOS/zoom.us',
            '/Applications/WhatsApp.app/Contents/MacOS/WhatsApp'
        ]
        
        for app_path in trusted_apps:
            if os.path.exists(app_path):
                try:
                    signature = self._calculate_file_hash(app_path)
                    self.trusted_signatures.add(signature)
                except Exception as e:
                    logger.warning(f"Could not calculate signature for {app_path}: {e}")
        
        logger.info(f"Loaded {len(self.trusted_signatures)} trusted signatures")
    
    def create_baseline(self, app_path: str, app_name: str = None, 
                       app_version: str = None) -> IntegrityBaseline:
        """Create integrity baseline for an application"""
        logger.info(f"Creating integrity baseline for {app_path}")
        
        if not os.path.exists(app_path):
            raise FileNotFoundError(f"Application not found: {app_path}")
        
        app_id = hashlib.sha256(app_path.encode()).hexdigest()[:16]
        
        if not app_name:
            app_name = os.path.basename(app_path)
        
        if not app_version:
            app_version = "unknown"
        
        # Calculate main binary hash
        baseline_hash = self._calculate_file_hash(app_path)
        
        # Scan all files in application bundle
        file_signatures = {}
        if os.path.isdir(app_path):  # Application bundle
            for root, dirs, files in os.walk(app_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        file_hash = self._calculate_file_hash(file_path)
                        relative_path = os.path.relpath(file_path, app_path)
                        file_signatures[relative_path] = file_hash
                    except Exception as e:
                        logger.warning(f"Could not hash file {file_path}: {e}")
        else:  # Single binary
            file_signatures[os.path.basename(app_path)] = baseline_hash
        
        # Get process characteristics if running
        process_characteristics = {}
        loaded_libraries = []
        memory_regions = {}
        
        if psutil:
            try:
                # Find running process
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        if proc.info['exe'] == app_path:
                            process_characteristics = self._get_process_characteristics(proc)
                            loaded_libraries = self._get_loaded_libraries(proc)
                            memory_regions = self._get_memory_regions(proc)
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                logger.warning(f"Could not get process information: {e}")
        
        baseline = IntegrityBaseline(
            app_id=app_id,
            app_name=app_name,
            app_version=app_version,
            app_path=app_path,
            baseline_hash=baseline_hash,
            file_signatures=file_signatures,
            memory_regions=memory_regions,
            loaded_libraries=loaded_libraries,
            process_characteristics=process_characteristics,
            baseline_timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            verification_methods=[
                VerificationMethod.HASH_COMPARISON,
                VerificationMethod.DIGITAL_SIGNATURE,
                VerificationMethod.RUNTIME_ANALYSIS
            ]
        )
        
        self.app_baselines[app_id] = baseline
        logger.info(f"Created baseline for {app_name} with {len(file_signatures)} files")
        
        return baseline
    
    def verify_integrity(self, app_path: str, baseline_id: str = None) -> IntegrityReport:
        """Verify application integrity against baseline"""
        start_time = time.time()
        logger.info(f"Verifying integrity of {app_path}")
        
        # Find or create baseline
        if baseline_id:
            baseline = self.app_baselines.get(baseline_id)
            if not baseline:
                raise ValueError(f"Baseline not found: {baseline_id}")
        else:
            # Try to find existing baseline
            app_id = hashlib.sha256(app_path.encode()).hexdigest()[:16]
            baseline = self.app_baselines.get(app_id)
            if not baseline:
                # Create new baseline
                baseline = self.create_baseline(app_path)
        
        # Perform verification
        tamper_detections = []
        baseline_comparison = {}
        signature_verification = {}
        runtime_analysis = {}
        
        # 1. Hash comparison
        hash_results = self._verify_file_hashes(app_path, baseline)
        baseline_comparison.update(hash_results)
        
        if not hash_results.get('main_binary_match', True):
            tamper_detections.append(TamperDetection(
                tamper_type=TamperType.BINARY_MODIFICATION,
                severity="high",
                description="Main application binary has been modified",
                affected_files=[app_path],
                detection_method=VerificationMethod.HASH_COMPARISON,
                evidence={'expected_hash': baseline.baseline_hash, 'actual_hash': hash_results.get('actual_hash')},
                confidence_score=0.95,
                detection_timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            ))
        
        # 2. Digital signature verification
        sig_results = self._verify_digital_signature(app_path)
        signature_verification.update(sig_results)
        
        if not sig_results.get('signature_valid', True):
            tamper_detections.append(TamperDetection(
                tamper_type=TamperType.SIGNATURE_INVALID,
                severity="critical",
                description="Digital signature verification failed",
                affected_files=[app_path],
                detection_method=VerificationMethod.DIGITAL_SIGNATURE,
                evidence=sig_results,
                confidence_score=0.9,
                detection_timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            ))
        
        # 3. Runtime analysis
        if psutil:
            runtime_results = self._perform_runtime_analysis(app_path, baseline)
            runtime_analysis.update(runtime_results)
            
            # Check for runtime tampering
            if runtime_results.get('memory_anomalies'):
                tamper_detections.append(TamperDetection(
                    tamper_type=TamperType.MEMORY_CORRUPTION,
                    severity="high",
                    description="Memory anomalies detected",
                    affected_files=[app_path],
                    detection_method=VerificationMethod.RUNTIME_ANALYSIS,
                    evidence=runtime_results.get('memory_anomalies', {}),
                    confidence_score=0.8,
                    detection_timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
                ))
            
            if runtime_results.get('unexpected_libraries'):
                tamper_detections.append(TamperDetection(
                    tamper_type=TamperType.LIBRARY_HIJACKING,
                    severity="medium",
                    description="Unexpected libraries loaded",
                    affected_files=runtime_results.get('unexpected_libraries', []),
                    detection_method=VerificationMethod.RUNTIME_ANALYSIS,
                    evidence={'libraries': runtime_results.get('unexpected_libraries', [])},
                    confidence_score=0.7,
                    detection_timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
                ))
        
        # 4. YARA rule scanning
        if self.yara_rules:
            yara_results = self._scan_with_yara(app_path)
            if yara_results:
                for match in yara_results:
                    tamper_detections.append(TamperDetection(
                        tamper_type=TamperType.CODE_INJECTION,
                        severity=match.get('severity', 'medium'),
                        description=f"YARA rule matched: {match['rule']}",
                        affected_files=[app_path],
                        detection_method=VerificationMethod.YARA_RULES,
                        evidence=match,
                        confidence_score=0.85,
                        detection_timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
                    ))
        
        # Calculate overall status and integrity score
        overall_status, integrity_score = self._calculate_integrity_status(tamper_detections)
        
        # Generate recommendations and mitigation actions
        recommendations = self._generate_recommendations(tamper_detections, integrity_score)
        mitigation_actions = self._generate_mitigation_actions(tamper_detections, overall_status)
        
        # Create report
        verification_duration = time.time() - start_time
        
        report = IntegrityReport(
            app_id=baseline.app_id,
            app_name=baseline.app_name,
            app_path=app_path,
            verification_timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            overall_status=overall_status,
            integrity_score=integrity_score,
            baseline_comparison=baseline_comparison,
            tamper_detections=tamper_detections,
            signature_verification=signature_verification,
            runtime_analysis=runtime_analysis,
            recommendations=recommendations,
            mitigation_actions=mitigation_actions,
            verification_duration=verification_duration
        )
        
        # Update statistics
        self.detection_stats['total_verifications'] += 1
        if overall_status == IntegrityStatus.COMPROMISED:
            self.detection_stats['compromised_apps'] += 1
        elif overall_status == IntegrityStatus.SUSPICIOUS:
            self.detection_stats['suspicious_apps'] += 1
        
        self.detection_stats['tamper_detections'] += len(tamper_detections)
        
        logger.info(f"Integrity verification completed: {overall_status.value} (Score: {integrity_score:.1f}/100)")
        return report
    
    def _calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate file hash"""
        hash_func = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def _verify_file_hashes(self, app_path: str, baseline: IntegrityBaseline) -> Dict[str, Any]:
        """Verify file hashes against baseline"""
        results = {
            'main_binary_match': True,
            'file_matches': {},
            'modified_files': [],
            'new_files': [],
            'deleted_files': []
        }
        
        try:
            # Check main binary
            current_hash = self._calculate_file_hash(app_path)
            results['actual_hash'] = current_hash
            results['main_binary_match'] = (current_hash == baseline.baseline_hash)
            
            # Check all files in baseline
            if os.path.isdir(app_path):
                current_files = {}
                for root, dirs, files in os.walk(app_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, app_path)
                        try:
                            file_hash = self._calculate_file_hash(file_path)
                            current_files[relative_path] = file_hash
                        except Exception as e:
                            logger.warning(f"Could not hash file {file_path}: {e}")
                
                # Compare with baseline
                for rel_path, baseline_hash in baseline.file_signatures.items():
                    if rel_path in current_files:
                        match = current_files[rel_path] == baseline_hash
                        results['file_matches'][rel_path] = match
                        if not match:
                            results['modified_files'].append(rel_path)
                    else:
                        results['deleted_files'].append(rel_path)
                
                # Check for new files
                for rel_path in current_files:
                    if rel_path not in baseline.file_signatures:
                        results['new_files'].append(rel_path)
            
        except Exception as e:
            logger.error(f"Error verifying file hashes: {e}")
            results['error'] = str(e)
        
        return results
    
    def _verify_digital_signature(self, app_path: str) -> Dict[str, Any]:
        """Verify digital signature"""
        results = {
            'signature_valid': False,
            'certificate_valid': False,
            'certificate_info': {},
            'signature_timestamp': None,
            'error': None
        }
        
        try:
            if sys.platform == 'darwin':  # macOS
                # Use codesign to verify signature
                cmd = ['codesign', '-v', '-v', app_path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    results['signature_valid'] = True
                    
                    # Get certificate information
                    cert_cmd = ['codesign', '-d', '-v', '-v', '-v', app_path]
                    cert_result = subprocess.run(cert_cmd, capture_output=True, text=True)
                    
                    if cert_result.returncode == 0:
                        # Parse certificate info from output
                        cert_info = self._parse_codesign_output(cert_result.stderr)
                        results['certificate_info'] = cert_info
                        results['certificate_valid'] = True
                else:
                    results['error'] = result.stderr
                    
            elif sys.platform.startswith('linux'):
                # Linux signature verification (if available)
                # This would require specific tools like osslsigncode
                results['error'] = "Linux signature verification not implemented"
                
            elif sys.platform == 'win32':
                # Windows signature verification
                # This would use Windows APIs or signtool
                results['error'] = "Windows signature verification not implemented"
                
        except Exception as e:
            logger.error(f"Error verifying digital signature: {e}")
            results['error'] = str(e)
        
        return results
    
    def _parse_codesign_output(self, output: str) -> Dict[str, Any]:
        """Parse codesign output for certificate information"""
        cert_info = {}
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if 'Authority=' in line:
                cert_info['authority'] = line.split('Authority=')[1]
            elif 'TeamIdentifier=' in line:
                cert_info['team_identifier'] = line.split('TeamIdentifier=')[1]
            elif 'Timestamp=' in line:
                cert_info['timestamp'] = line.split('Timestamp=')[1]
            elif 'Identifier=' in line:
                cert_info['identifier'] = line.split('Identifier=')[1]
        
        return cert_info
    
    def _perform_runtime_analysis(self, app_path: str, baseline: IntegrityBaseline) -> Dict[str, Any]:
        """Perform runtime analysis of the application"""
        results = {
            'process_found': False,
            'memory_anomalies': {},
            'unexpected_libraries': [],
            'process_characteristics': {},
            'debugger_detected': False,
            'injection_detected': False
        }
        
        if not psutil:
            results['error'] = "psutil not available"
            return results
        
        try:
            # Find running process
            target_process = None
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if proc.info['exe'] == app_path:
                        target_process = proc
                        results['process_found'] = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if not target_process:
                results['error'] = "Process not running"
                return results
            
            # Get current process characteristics
            current_characteristics = self._get_process_characteristics(target_process)
            results['process_characteristics'] = current_characteristics
            
            # Compare with baseline
            if baseline.process_characteristics:
                # Check for significant changes
                baseline_memory = baseline.process_characteristics.get('memory_info', {})
                current_memory = current_characteristics.get('memory_info', {})
                
                if baseline_memory and current_memory:
                    memory_diff = abs(current_memory.get('rss', 0) - baseline_memory.get('rss', 0))
                    if memory_diff > baseline_memory.get('rss', 0) * 0.5:  # 50% increase
                        results['memory_anomalies']['excessive_memory_usage'] = {
                            'baseline_rss': baseline_memory.get('rss', 0),
                            'current_rss': current_memory.get('rss', 0),
                            'difference': memory_diff
                        }
            
            # Check loaded libraries
            current_libraries = self._get_loaded_libraries(target_process)
            if baseline.loaded_libraries:
                unexpected = set(current_libraries) - set(baseline.loaded_libraries)
                results['unexpected_libraries'] = list(unexpected)
            
            # Check for debugger
            results['debugger_detected'] = self._check_debugger_presence(target_process)
            
            # Check for code injection indicators
            results['injection_detected'] = self._check_code_injection(target_process)
            
        except Exception as e:
            logger.error(f"Error in runtime analysis: {e}")
            results['error'] = str(e)
        
        return results
    
    def _get_process_characteristics(self, process: Any) -> Dict[str, Any]:
        """Get process characteristics"""
        try:
            return {
                'pid': process.pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'create_time': process.create_time(),
                'memory_info': process.memory_info()._asdict(),
                'cpu_percent': process.cpu_percent(),
                'num_threads': process.num_threads(),
                'status': process.status()
            }
        except Exception as e:
            logger.warning(f"Could not get process characteristics: {e}")
            return {}
    
    def _get_loaded_libraries(self, process: Any) -> List[str]:
        """Get loaded libraries/modules"""
        try:
            if hasattr(process, 'memory_maps'):
                maps = process.memory_maps()
                return [m.path for m in maps if m.path and os.path.exists(m.path)]
            else:
                return []
        except Exception as e:
            logger.warning(f"Could not get loaded libraries: {e}")
            return []
    
    def _get_memory_regions(self, process: Any) -> Dict[str, str]:
        """Get memory region hashes"""
        regions = {}
        try:
            if hasattr(process, 'memory_maps'):
                maps = process.memory_maps()
                for i, m in enumerate(maps[:10]):  # Limit to first 10 regions
                    region_name = f"region_{i}_{m.addr}"
                    # In a real implementation, you would read and hash memory content
                    # This is a simplified placeholder
                    regions[region_name] = hashlib.sha256(f"{m.addr}_{m.perms}".encode()).hexdigest()[:16]
        except Exception as e:
            logger.warning(f"Could not get memory regions: {e}")
        
        return regions
    
    def _check_debugger_presence(self, process: Any) -> bool:
        """Check if debugger is attached"""
        try:
            # Check for common debugger indicators
            if sys.platform == 'darwin':
                # On macOS, check for debugging flags
                cmd = ['ps', '-o', 'flags', '-p', str(process.pid)]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    # Check for debugging flags in output
                    return 'T' in result.stdout  # Traced flag
            
            return False
        except Exception:
            return False
    
    def _check_code_injection(self, process: Any) -> bool:
        """Check for code injection indicators"""
        try:
            # Check for unusual memory patterns
            if hasattr(process, 'memory_maps'):
                maps = process.memory_maps()
                
                # Look for executable memory regions that are not backed by files
                for m in maps:
                    if 'x' in m.perms and not m.path:
                        return True  # Executable memory without file backing
            
            return False
        except Exception:
            return False
    
    def _scan_with_yara(self, app_path: str) -> List[Dict[str, Any]]:
        """Scan with YARA rules"""
        if not self.yara_rules:
            return []
        
        matches = []
        try:
            yara_matches = self.yara_rules.match(app_path)
            
            for match in yara_matches:
                match_info = {
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [(s.identifier, s.instances) for s in match.strings]
                }
                
                # Extract severity from meta
                severity = 'medium'
                for meta_key, meta_value in match.meta.items():
                    if meta_key == 'severity':
                        severity = meta_value
                        break
                
                match_info['severity'] = severity
                matches.append(match_info)
                
        except Exception as e:
            logger.error(f"YARA scanning failed: {e}")
        
        return matches
    
    def _calculate_integrity_status(self, tamper_detections: List[TamperDetection]) -> Tuple[IntegrityStatus, float]:
        """Calculate overall integrity status and score"""
        if not tamper_detections:
            return IntegrityStatus.VERIFIED, 100.0
        
        # Calculate score based on detections
        score = 100.0
        critical_count = 0
        high_count = 0
        medium_count = 0
        
        for detection in tamper_detections:
            if detection.severity == 'critical':
                critical_count += 1
                score -= 40.0
            elif detection.severity == 'high':
                high_count += 1
                score -= 25.0
            elif detection.severity == 'medium':
                medium_count += 1
                score -= 15.0
            else:  # low
                score -= 5.0
        
        score = max(0.0, score)
        
        # Determine status
        if critical_count > 0 or score < 30:
            status = IntegrityStatus.COMPROMISED
        elif high_count > 0 or score < 60:
            status = IntegrityStatus.SUSPICIOUS
        elif medium_count > 0 or score < 80:
            status = IntegrityStatus.SUSPICIOUS
        else:
            status = IntegrityStatus.VERIFIED
        
        return status, score
    
    def _generate_recommendations(self, tamper_detections: List[TamperDetection], 
                                integrity_score: float) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if integrity_score < 30:
            recommendations.extend([
                "🚨 CRITICAL: Application integrity severely compromised",
                "Immediately stop using this application",
                "Quarantine the application files",
                "Perform full system malware scan",
                "Reinstall application from trusted source"
            ])
        elif integrity_score < 60:
            recommendations.extend([
                "⚠️ WARNING: Application integrity compromised",
                "Exercise extreme caution when using this application",
                "Consider reinstalling from trusted source",
                "Monitor application behavior closely",
                "Update security software and scan system"
            ])
        elif integrity_score < 80:
            recommendations.extend([
                "⚠️ CAUTION: Potential integrity issues detected",
                "Verify application source and authenticity",
                "Monitor for unusual behavior",
                "Consider updating to latest version"
            ])
        else:
            recommendations.extend([
                "✅ Application integrity verified",
                "Continue normal usage",
                "Keep application updated",
                "Regular integrity checks recommended"
            ])
        
        # Specific recommendations based on detections
        detection_types = {d.tamper_type for d in tamper_detections}
        
        if TamperType.CODE_INJECTION in detection_types:
            recommendations.append("🔍 Code injection detected - scan for malware")
        
        if TamperType.SIGNATURE_INVALID in detection_types:
            recommendations.append("📝 Invalid signature - verify application authenticity")
        
        if TamperType.LIBRARY_HIJACKING in detection_types:
            recommendations.append("📚 Library hijacking detected - check system integrity")
        
        return recommendations
    
    def _generate_mitigation_actions(self, tamper_detections: List[TamperDetection], 
                                   status: IntegrityStatus) -> List[str]:
        """Generate mitigation actions"""
        actions = []
        
        if status == IntegrityStatus.COMPROMISED:
            actions.extend([
                "Quarantine application immediately",
                "Block application execution",
                "Notify security team",
                "Initiate incident response",
                "Preserve evidence for analysis"
            ])
        elif status == IntegrityStatus.SUSPICIOUS:
            actions.extend([
                "Increase monitoring",
                "Restrict application privileges",
                "Log all application activity",
                "Schedule detailed analysis"
            ])
        
        # Specific actions based on detection types
        for detection in tamper_detections:
            if detection.tamper_type == TamperType.CODE_INJECTION:
                actions.append("Terminate process and scan memory")
            elif detection.tamper_type == TamperType.SIGNATURE_INVALID:
                actions.append("Verify application source")
            elif detection.tamper_type == TamperType.LIBRARY_HIJACKING:
                actions.append("Check library integrity")
        
        return actions
    
    def start_monitoring(self, app_paths: List[str]) -> None:
        """Start continuous integrity monitoring"""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return
        
        self.monitored_apps = set(app_paths)
        self.monitoring_active = True
        
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitoring_thread.start()
        
        logger.info(f"Started integrity monitoring for {len(app_paths)} applications")
    
    def stop_monitoring(self) -> None:
        """Stop continuous monitoring"""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        logger.info("Stopped integrity monitoring")
    
    def _monitoring_loop(self) -> None:
        """Continuous monitoring loop"""
        while self.monitoring_active:
            try:
                for app_path in self.monitored_apps.copy():
                    if not os.path.exists(app_path):
                        continue
                    
                    try:
                        report = self.verify_integrity(app_path)
                        
                        if report.overall_status in [IntegrityStatus.COMPROMISED, IntegrityStatus.SUSPICIOUS]:
                            logger.warning(f"Integrity issue detected in {app_path}: {report.overall_status.value}")
                            
                            # Trigger alerts or actions based on severity
                            if report.overall_status == IntegrityStatus.COMPROMISED:
                                logger.critical(f"CRITICAL: {app_path} integrity compromised!")
                    
                    except Exception as e:
                        logger.error(f"Error monitoring {app_path}: {e}")
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get integrity verification statistics"""
        return {
            'total_verifications': self.detection_stats['total_verifications'],
            'compromised_apps': self.detection_stats['compromised_apps'],
            'suspicious_apps': self.detection_stats['suspicious_apps'],
            'tamper_detections': self.detection_stats['tamper_detections'],
            'false_positives': self.detection_stats['false_positives'],
            'baselines_created': len(self.app_baselines),
            'trusted_signatures': len(self.trusted_signatures),
            'monitoring_active': self.monitoring_active,
            'monitored_apps': len(self.monitored_apps) if self.monitoring_active else 0
        }
    
    def export_baselines(self, filename: str) -> None:
        """Export application baselines"""
        try:
            export_data = {
                'export_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_baselines': len(self.app_baselines),
                'baselines': {app_id: asdict(baseline) for app_id, baseline in self.app_baselines.items()}
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Exported {len(self.app_baselines)} baselines to {filename}")
            
        except Exception as e:
            logger.error(f"Failed to export baselines: {e}")
    
    def import_baselines(self, filename: str) -> None:
        """Import application baselines"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            baselines = data.get('baselines', {})
            imported_count = 0
            
            for app_id, baseline_data in baselines.items():
                try:
                    # Convert dict back to IntegrityBaseline
                    baseline = IntegrityBaseline(**baseline_data)
                    self.app_baselines[app_id] = baseline
                    imported_count += 1
                except Exception as e:
                    logger.warning(f"Could not import baseline {app_id}: {e}")
            
            logger.info(f"Imported {imported_count} baselines from {filename}")
            
        except Exception as e:
            logger.error(f"Failed to import baselines: {e}")