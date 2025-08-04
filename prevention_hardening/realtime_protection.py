"""Real-time Protection Engine

Provides real-time security protection including:
- Zero-click exploit detection
- Malicious link scanning
- App integrity verification
- Real-time threat monitoring
- Behavioral anomaly detection
"""

import os
import re
import json
import time
import hashlib
import threading
import subprocess
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse
from loguru import logger

try:
    import requests
except ImportError:
    requests = None

try:
    import psutil
except ImportError:
    psutil = None


class ThreatType(Enum):
    """Types of threats"""
    ZERO_CLICK_EXPLOIT = "zero_click_exploit"
    MALICIOUS_LINK = "malicious_link"
    APP_TAMPERING = "app_tampering"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    NETWORK_ANOMALY = "network_anomaly"
    FILE_MODIFICATION = "file_modification"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProtectionStatus(Enum):
    """Protection status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    UPDATING = "updating"


@dataclass
class ThreatDetection:
    """Threat detection result"""
    threat_id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    description: str
    source: str
    target: str
    timestamp: str
    evidence: Dict[str, Any]
    confidence_score: float
    mitigation_actions: List[str]
    blocked: bool = False
    false_positive: bool = False


@dataclass
class AppIntegrityCheck:
    """App integrity verification result"""
    app_path: str
    app_name: str
    bundle_id: str
    expected_hash: str
    current_hash: str
    is_valid: bool
    signature_valid: bool
    last_modified: str
    suspicious_changes: List[str]
    risk_score: float


@dataclass
class LinkScanResult:
    """Malicious link scan result"""
    url: str
    is_malicious: bool
    threat_types: List[str]
    reputation_score: float
    scan_engines: Dict[str, str]
    redirect_chain: List[str]
    final_url: str
    scan_timestamp: str
    blocked: bool = False


@dataclass
class ExploitSignature:
    """Zero-click exploit signature"""
    signature_id: str
    name: str
    description: str
    pattern: str
    target_apps: List[str]
    cve_ids: List[str]
    severity: ThreatSeverity
    detection_method: str
    last_updated: str


@dataclass
class ProtectionReport:
    """Real-time protection report"""
    timestamp: str
    protection_status: ProtectionStatus
    monitoring_duration: float
    threats_detected: int
    threats_blocked: int
    apps_verified: int
    links_scanned: int
    malicious_links_blocked: int
    integrity_violations: int
    exploit_attempts: int
    detections: List[ThreatDetection]
    app_integrity_results: List[AppIntegrityCheck]
    link_scan_results: List[LinkScanResult]
    recommendations: List[str]
    overall_security_score: float


class RealTimeProtectionEngine:
    """Real-time security protection engine"""
    
    def __init__(self):
        self.protection_active = False
        self.monitoring_threads: List[threading.Thread] = []
        
        # Detection storage
        self.threat_detections: List[ThreatDetection] = []
        self.app_integrity_cache: Dict[str, AppIntegrityCheck] = {}
        self.link_scan_cache: Dict[str, LinkScanResult] = {}
        
        # Exploit signatures
        self.exploit_signatures: Dict[str, ExploitSignature] = {}
        
        # Malicious URL patterns and databases
        self.malicious_url_patterns: List[str] = []
        self.malicious_domains: Set[str] = set()
        self.suspicious_tlds: Set[str] = set()
        
        # App integrity baselines
        self.app_baselines: Dict[str, Dict[str, str]] = {}
        
        # Behavioral monitoring
        self.process_behaviors: Dict[int, Dict[str, Any]] = {}
        self.network_behaviors: Dict[str, Dict[str, Any]] = {}
        
        # Protection callbacks
        self.threat_callbacks: List[Callable[[ThreatDetection], None]] = []
        
        # Initialize protection components
        self._initialize_exploit_signatures()
        self._initialize_malicious_patterns()
        self._load_app_baselines()
        
        logger.info("RealTimeProtectionEngine initialized")
    
    def _initialize_exploit_signatures(self) -> None:
        """Initialize zero-click exploit signatures"""
        signatures = [
            ExploitSignature(
                signature_id="pegasus_imessage_2021",
                name="Pegasus iMessage Exploit",
                description="Zero-click exploit targeting iMessage via malformed GIF",
                pattern=r".*\.gif.*JFIF.*\x00\x00\x00\x00.*",
                target_apps=["com.apple.MobileSMS", "Messages"],
                cve_ids=["CVE-2021-30860"],
                severity=ThreatSeverity.CRITICAL,
                detection_method="pattern_matching",
                last_updated="2021-09-13"
            ),
            ExploitSignature(
                signature_id="forcedentry_pdf_2021",
                name="ForcedEntry PDF Exploit",
                description="Zero-click exploit via malicious PDF in iMessage",
                pattern=r".*\.pdf.*<<\/JavaScript.*eval\(.*\).*>>",
                target_apps=["com.apple.MobileSMS", "Preview", "Safari"],
                cve_ids=["CVE-2021-30860"],
                severity=ThreatSeverity.CRITICAL,
                detection_method="content_analysis",
                last_updated="2021-09-13"
            ),
            ExploitSignature(
                signature_id="whatsapp_buffer_overflow",
                name="WhatsApp Buffer Overflow",
                description="Buffer overflow in WhatsApp voice call handling",
                pattern=r".*WhatsApp.*voice.*call.*buffer.*overflow.*",
                target_apps=["com.whatsapp.WhatsApp", "WhatsApp"],
                cve_ids=["CVE-2019-3568"],
                severity=ThreatSeverity.HIGH,
                detection_method="behavioral_analysis",
                last_updated="2019-05-13"
            ),
            ExploitSignature(
                signature_id="telegram_media_exploit",
                name="Telegram Media Processing Exploit",
                description="Exploit in Telegram media file processing",
                pattern=r".*telegram.*media.*processing.*exploit.*",
                target_apps=["org.telegram.desktop", "Telegram"],
                cve_ids=["CVE-2020-17448"],
                severity=ThreatSeverity.HIGH,
                detection_method="file_analysis",
                last_updated="2020-08-11"
            )
        ]
        
        for signature in signatures:
            self.exploit_signatures[signature.signature_id] = signature
        
        logger.info(f"Loaded {len(self.exploit_signatures)} exploit signatures")
    
    def _initialize_malicious_patterns(self) -> None:
        """Initialize malicious URL patterns and domains"""
        # Malicious URL patterns
        self.malicious_url_patterns = [
            r".*\.tk/.*",  # Suspicious TLD
            r".*\.ml/.*",  # Suspicious TLD
            r".*\.ga/.*",  # Suspicious TLD
            r".*\.cf/.*",  # Suspicious TLD
            r".*bit\.ly/[a-zA-Z0-9]{6}.*",  # Suspicious short URLs
            r".*tinyurl\.com/[a-zA-Z0-9]{7}.*",  # Suspicious short URLs
            r".*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.*",  # IP-based URLs
            r".*phishing.*",
            r".*malware.*",
            r".*trojan.*",
            r".*virus.*download.*",
            r".*free.*money.*click.*",
            r".*urgent.*security.*update.*"
        ]
        
        # Known malicious domains (examples)
        self.malicious_domains.update([
            "malware.example.com",
            "phishing.test.org",
            "suspicious.domain.net",
            "fake-bank.com",
            "virus-download.org"
        ])
        
        # Suspicious TLDs
        self.suspicious_tlds.update([
            ".tk", ".ml", ".ga", ".cf", ".pw", ".top", ".click", ".download"
        ])
        
        logger.info(f"Loaded {len(self.malicious_url_patterns)} URL patterns and {len(self.malicious_domains)} malicious domains")
    
    def _load_app_baselines(self) -> None:
        """Load application integrity baselines"""
        baseline_file = "app_baselines.json"
        
        try:
            if os.path.exists(baseline_file):
                with open(baseline_file, 'r') as f:
                    self.app_baselines = json.load(f)
                logger.info(f"Loaded baselines for {len(self.app_baselines)} applications")
            else:
                logger.info("No existing app baselines found, will create new ones")
        except Exception as e:
            logger.error(f"Failed to load app baselines: {e}")
    
    def start_protection(self) -> None:
        """Start real-time protection monitoring"""
        if self.protection_active:
            logger.warning("Real-time protection already active")
            return
        
        self.protection_active = True
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self._monitor_zero_click_exploits, daemon=True),
            threading.Thread(target=self._monitor_app_integrity, daemon=True),
            threading.Thread(target=self._monitor_network_behavior, daemon=True),
            threading.Thread(target=self._monitor_file_system, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
            self.monitoring_threads.append(thread)
        
        logger.info("Real-time protection started")
    
    def stop_protection(self) -> None:
        """Stop real-time protection monitoring"""
        self.protection_active = False
        
        # Wait for threads to finish
        for thread in self.monitoring_threads:
            thread.join(timeout=5)
        
        self.monitoring_threads.clear()
        logger.info("Real-time protection stopped")
    
    def _monitor_zero_click_exploits(self) -> None:
        """Monitor for zero-click exploits"""
        while self.protection_active:
            try:
                # Monitor messaging apps for suspicious activity
                self._check_messaging_apps()
                
                # Monitor network traffic for exploit patterns
                self._check_network_exploits()
                
                # Monitor file system for exploit artifacts
                self._check_exploit_artifacts()
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                logger.error(f"Error in zero-click exploit monitoring: {e}")
                time.sleep(5)
    
    def _check_messaging_apps(self) -> None:
        """Check messaging apps for suspicious activity"""
        if not psutil:
            return
        
        messaging_apps = [
            "Messages", "WhatsApp", "Telegram", "Signal", "Viber", "WeChat"
        ]
        
        try:
            for process in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent']):
                if process.info['name'] in messaging_apps:
                    # Check for unusual memory usage
                    memory_mb = process.info['memory_info'].rss / 1024 / 1024
                    cpu_percent = process.info['cpu_percent']
                    
                    # Detect anomalous resource usage
                    if memory_mb > 500 or cpu_percent > 80:  # Thresholds
                        self._create_threat_detection(
                            ThreatType.ZERO_CLICK_EXPLOIT,
                            ThreatSeverity.HIGH,
                            f"Suspicious resource usage in {process.info['name']}",
                            f"Process: {process.info['name']}",
                            f"PID: {process.info['pid']}",
                            {
                                "memory_mb": memory_mb,
                                "cpu_percent": cpu_percent,
                                "pid": process.info['pid']
                            },
                            0.7
                        )
                        
        except Exception as e:
            logger.error(f"Error checking messaging apps: {e}")
    
    def _check_network_exploits(self) -> None:
        """Check network traffic for exploit patterns"""
        # This would analyze network packets for exploit signatures
        # For now, simulate detection
        pass
    
    def _check_exploit_artifacts(self) -> None:
        """Check file system for exploit artifacts"""
        suspicious_paths = [
            "/tmp",
            "/var/tmp",
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop")
        ]
        
        for path in suspicious_paths:
            if os.path.exists(path):
                try:
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            if self._is_suspicious_file(file_path):
                                self._analyze_suspicious_file(file_path)
                except Exception as e:
                    logger.error(f"Error checking {path}: {e}")
    
    def _is_suspicious_file(self, file_path: str) -> bool:
        """Check if file is suspicious"""
        suspicious_extensions = [".scr", ".pif", ".bat", ".cmd", ".com"]
        suspicious_names = ["exploit", "payload", "backdoor", "trojan"]
        
        file_name = os.path.basename(file_path).lower()
        
        # Check extension
        if any(file_name.endswith(ext) for ext in suspicious_extensions):
            return True
        
        # Check name patterns
        if any(name in file_name for name in suspicious_names):
            return True
        
        # Check for recently created files with suspicious characteristics
        try:
            stat = os.stat(file_path)
            if time.time() - stat.st_ctime < 3600:  # Created in last hour
                if stat.st_size > 10 * 1024 * 1024:  # Larger than 10MB
                    return True
        except Exception:
            pass
        
        return False
    
    def _analyze_suspicious_file(self, file_path: str) -> None:
        """Analyze suspicious file for exploits"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # Read first 1MB
            
            # Check against exploit signatures
            for signature in self.exploit_signatures.values():
                if re.search(signature.pattern.encode(), content, re.IGNORECASE):
                    self._create_threat_detection(
                        ThreatType.ZERO_CLICK_EXPLOIT,
                        signature.severity,
                        f"Exploit signature detected: {signature.name}",
                        file_path,
                        signature.signature_id,
                        {
                            "signature_id": signature.signature_id,
                            "cve_ids": signature.cve_ids,
                            "file_size": len(content)
                        },
                        0.9
                    )
                    
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
    
    def _monitor_app_integrity(self) -> None:
        """Monitor application integrity"""
        while self.protection_active:
            try:
                self._verify_critical_apps()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"Error in app integrity monitoring: {e}")
                time.sleep(60)
    
    def _verify_critical_apps(self) -> None:
        """Verify integrity of critical applications"""
        critical_apps = [
            "/Applications/Safari.app",
            "/Applications/Mail.app",
            "/Applications/Messages.app",
            "/System/Applications/Contacts.app"
        ]
        
        for app_path in critical_apps:
            if os.path.exists(app_path):
                integrity_result = self.verify_app_integrity(app_path)
                if integrity_result and not integrity_result.is_valid:
                    self._create_threat_detection(
                        ThreatType.APP_TAMPERING,
                        ThreatSeverity.HIGH,
                        f"App integrity violation: {integrity_result.app_name}",
                        app_path,
                        "integrity_check",
                        {
                            "expected_hash": integrity_result.expected_hash,
                            "current_hash": integrity_result.current_hash,
                            "suspicious_changes": integrity_result.suspicious_changes
                        },
                        integrity_result.risk_score / 100
                    )
    
    def verify_app_integrity(self, app_path: str) -> Optional[AppIntegrityCheck]:
        """Verify integrity of a specific application"""
        try:
            if not os.path.exists(app_path):
                return None
            
            # Get app information
            app_name = os.path.basename(app_path)
            bundle_id = self._get_bundle_id(app_path)
            
            # Calculate current hash
            current_hash = self._calculate_app_hash(app_path)
            
            # Get expected hash from baseline
            expected_hash = self.app_baselines.get(bundle_id, {}).get('hash', '')
            
            # If no baseline exists, create one
            if not expected_hash:
                expected_hash = current_hash
                if bundle_id not in self.app_baselines:
                    self.app_baselines[bundle_id] = {}
                self.app_baselines[bundle_id]['hash'] = expected_hash
                self._save_app_baselines()
            
            # Check signature validity
            signature_valid = self._verify_app_signature(app_path)
            
            # Get last modified time
            stat = os.stat(app_path)
            last_modified = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
            
            # Check for suspicious changes
            suspicious_changes = self._detect_suspicious_changes(app_path)
            
            # Calculate risk score
            risk_score = self._calculate_integrity_risk_score(
                current_hash == expected_hash, signature_valid, suspicious_changes
            )
            
            integrity_check = AppIntegrityCheck(
                app_path=app_path,
                app_name=app_name,
                bundle_id=bundle_id,
                expected_hash=expected_hash,
                current_hash=current_hash,
                is_valid=(current_hash == expected_hash and signature_valid),
                signature_valid=signature_valid,
                last_modified=last_modified,
                suspicious_changes=suspicious_changes,
                risk_score=risk_score
            )
            
            self.app_integrity_cache[app_path] = integrity_check
            return integrity_check
            
        except Exception as e:
            logger.error(f"Error verifying app integrity for {app_path}: {e}")
            return None
    
    def _get_bundle_id(self, app_path: str) -> str:
        """Get bundle ID from app"""
        try:
            info_plist = os.path.join(app_path, "Contents", "Info.plist")
            if os.path.exists(info_plist):
                result = subprocess.run(
                    ['plutil', '-extract', 'CFBundleIdentifier', 'raw', info_plist],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    return result.stdout.strip()
        except Exception:
            pass
        return os.path.basename(app_path)
    
    def _calculate_app_hash(self, app_path: str) -> str:
        """Calculate hash of application bundle"""
        hasher = hashlib.sha256()
        
        try:
            for root, dirs, files in os.walk(app_path):
                for file in sorted(files):  # Sort for consistent hashing
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'rb') as f:
                            for chunk in iter(lambda: f.read(4096), b""):
                                hasher.update(chunk)
                    except Exception:
                        continue  # Skip files that can't be read
            
            return hasher.hexdigest()
            
        except Exception as e:
            logger.error(f"Error calculating hash for {app_path}: {e}")
            return ""
    
    def _verify_app_signature(self, app_path: str) -> bool:
        """Verify application code signature"""
        try:
            result = subprocess.run(
                ['codesign', '-v', app_path],
                capture_output=True, text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _detect_suspicious_changes(self, app_path: str) -> List[str]:
        """Detect suspicious changes in app"""
        suspicious_changes = []
        
        try:
            # Check for unusual files
            for root, dirs, files in os.walk(app_path):
                for file in files:
                    if file.startswith('.') and not file.startswith('.DS_Store'):
                        suspicious_changes.append(f"Hidden file: {file}")
                    
                    if file.endswith(('.dylib', '.so')) and 'Frameworks' not in root:
                        suspicious_changes.append(f"Suspicious library: {file}")
            
            # Check for modified system files
            system_files = ['Info.plist', 'CodeResources']
            for sys_file in system_files:
                file_path = os.path.join(app_path, 'Contents', sys_file)
                if os.path.exists(file_path):
                    stat = os.stat(file_path)
                    if time.time() - stat.st_mtime < 86400:  # Modified in last 24 hours
                        suspicious_changes.append(f"Recently modified: {sys_file}")
                        
        except Exception as e:
            logger.error(f"Error detecting suspicious changes: {e}")
        
        return suspicious_changes
    
    def _calculate_integrity_risk_score(self, hash_valid: bool, signature_valid: bool, 
                                       suspicious_changes: List[str]) -> float:
        """Calculate integrity risk score"""
        score = 0.0
        
        if not hash_valid:
            score += 40.0
        
        if not signature_valid:
            score += 30.0
        
        score += len(suspicious_changes) * 10.0
        
        return min(score, 100.0)
    
    def _save_app_baselines(self) -> None:
        """Save application baselines to file"""
        try:
            with open("app_baselines.json", 'w') as f:
                json.dump(self.app_baselines, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save app baselines: {e}")
    
    def scan_link(self, url: str) -> LinkScanResult:
        """Scan URL for malicious content"""
        # Check cache first
        if url in self.link_scan_cache:
            cached_result = self.link_scan_cache[url]
            # Return cached result if less than 1 hour old
            if time.time() - time.mktime(time.strptime(cached_result.scan_timestamp, '%Y-%m-%d %H:%M:%S')) < 3600:
                return cached_result
        
        logger.info(f"Scanning URL: {url}")
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Initialize scan result
            scan_result = LinkScanResult(
                url=url,
                is_malicious=False,
                threat_types=[],
                reputation_score=100.0,
                scan_engines={},
                redirect_chain=[url],
                final_url=url,
                scan_timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )
            
            # Check against known malicious domains
            if domain in self.malicious_domains:
                scan_result.is_malicious = True
                scan_result.threat_types.append("known_malicious_domain")
                scan_result.reputation_score = 0.0
            
            # Check against malicious patterns
            for pattern in self.malicious_url_patterns:
                if re.match(pattern, url, re.IGNORECASE):
                    scan_result.is_malicious = True
                    scan_result.threat_types.append("suspicious_pattern")
                    scan_result.reputation_score -= 20.0
            
            # Check suspicious TLD
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    scan_result.threat_types.append("suspicious_tld")
                    scan_result.reputation_score -= 15.0
            
            # Check for URL shorteners
            shortener_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
            if any(domain.endswith(shortener) for shortener in shortener_domains):
                scan_result.threat_types.append("url_shortener")
                scan_result.reputation_score -= 10.0
                # Try to resolve the final URL
                final_url = self._resolve_shortened_url(url)
                if final_url and final_url != url:
                    scan_result.final_url = final_url
                    scan_result.redirect_chain.append(final_url)
                    # Recursively scan the final URL
                    final_scan = self.scan_link(final_url)
                    if final_scan.is_malicious:
                        scan_result.is_malicious = True
                        scan_result.threat_types.extend(final_scan.threat_types)
            
            # Check for IP-based URLs
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                scan_result.threat_types.append("ip_based_url")
                scan_result.reputation_score -= 25.0
            
            # Additional checks with external services (if available)
            if requests:
                scan_result.scan_engines.update(self._check_external_reputation(url))
            
            # Determine if malicious based on reputation score
            if scan_result.reputation_score < 50.0:
                scan_result.is_malicious = True
            
            # Cache the result
            self.link_scan_cache[url] = scan_result
            
            # Create threat detection if malicious
            if scan_result.is_malicious:
                self._create_threat_detection(
                    ThreatType.MALICIOUS_LINK,
                    ThreatSeverity.HIGH if scan_result.reputation_score < 25 else ThreatSeverity.MEDIUM,
                    f"Malicious URL detected: {url}",
                    url,
                    "link_scanner",
                    {
                        "threat_types": scan_result.threat_types,
                        "reputation_score": scan_result.reputation_score,
                        "final_url": scan_result.final_url
                    },
                    (100 - scan_result.reputation_score) / 100
                )
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return LinkScanResult(
                url=url,
                is_malicious=False,
                threat_types=["scan_error"],
                reputation_score=50.0,
                scan_engines={"error": str(e)},
                redirect_chain=[url],
                final_url=url,
                scan_timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
            )
    
    def _resolve_shortened_url(self, url: str) -> Optional[str]:
        """Resolve shortened URL to final destination"""
        if not requests:
            return None
        
        try:
            response = requests.head(url, allow_redirects=True, timeout=10)
            return response.url
        except Exception:
            return None
    
    def _check_external_reputation(self, url: str) -> Dict[str, str]:
        """Check URL reputation with external services"""
        results = {}
        
        # This would integrate with services like VirusTotal, URLVoid, etc.
        # For now, simulate the checks
        results["simulated_engine"] = "clean"
        
        return results
    
    def _monitor_network_behavior(self) -> None:
        """Monitor network behavior for anomalies"""
        while self.protection_active:
            try:
                self._analyze_network_connections()
                time.sleep(10)  # Check every 10 seconds
            except Exception as e:
                logger.error(f"Error in network behavior monitoring: {e}")
                time.sleep(30)
    
    def _analyze_network_connections(self) -> None:
        """Analyze network connections for suspicious behavior"""
        if not psutil:
            return
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    conn_key = f"{conn.raddr.ip}:{conn.raddr.port}"
                    
                    # Track connection behavior
                    if conn_key not in self.network_behaviors:
                        self.network_behaviors[conn_key] = {
                            'first_seen': time.time(),
                            'connection_count': 0,
                            'data_transferred': 0
                        }
                    
                    self.network_behaviors[conn_key]['connection_count'] += 1
                    
                    # Check for suspicious patterns
                    behavior = self.network_behaviors[conn_key]
                    
                    # High frequency connections
                    if behavior['connection_count'] > 100:  # Threshold
                        self._create_threat_detection(
                            ThreatType.NETWORK_ANOMALY,
                            ThreatSeverity.MEDIUM,
                            f"High frequency connections to {conn.raddr.ip}",
                            f"{conn.laddr.ip}:{conn.laddr.port}",
                            f"{conn.raddr.ip}:{conn.raddr.port}",
                            {
                                "connection_count": behavior['connection_count'],
                                "duration": time.time() - behavior['first_seen']
                            },
                            0.6
                        )
                        
        except Exception as e:
            logger.error(f"Error analyzing network connections: {e}")
    
    def _monitor_file_system(self) -> None:
        """Monitor file system for suspicious changes"""
        while self.protection_active:
            try:
                self._check_critical_file_changes()
                time.sleep(15)  # Check every 15 seconds
            except Exception as e:
                logger.error(f"Error in file system monitoring: {e}")
                time.sleep(60)
    
    def _check_critical_file_changes(self) -> None:
        """Check for changes to critical system files"""
        critical_paths = [
            "/etc/hosts",
            "/etc/passwd",
            "/System/Library/LaunchDaemons",
            "/Library/LaunchDaemons",
            os.path.expanduser("~/Library/LaunchAgents")
        ]
        
        for path in critical_paths:
            if os.path.exists(path):
                try:
                    if os.path.isfile(path):
                        stat = os.stat(path)
                        if time.time() - stat.st_mtime < 300:  # Modified in last 5 minutes
                            self._create_threat_detection(
                                ThreatType.FILE_MODIFICATION,
                                ThreatSeverity.HIGH,
                                f"Critical file modified: {path}",
                                path,
                                "file_monitor",
                                {
                                    "modification_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime)),
                                    "file_size": stat.st_size
                                },
                                0.8
                            )
                except Exception as e:
                    logger.error(f"Error checking {path}: {e}")
    
    def _create_threat_detection(self, threat_type: ThreatType, severity: ThreatSeverity,
                               description: str, source: str, target: str,
                               evidence: Dict[str, Any], confidence: float) -> None:
        """Create and store threat detection"""
        threat_id = f"{threat_type.value}_{int(time.time())}_{hash(source + target) % 10000}"
        
        detection = ThreatDetection(
            threat_id=threat_id,
            threat_type=threat_type,
            severity=severity,
            description=description,
            source=source,
            target=target,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            evidence=evidence,
            confidence_score=confidence,
            mitigation_actions=self._get_mitigation_actions(threat_type, severity)
        )
        
        self.threat_detections.append(detection)
        
        # Call registered callbacks
        for callback in self.threat_callbacks:
            try:
                callback(detection)
            except Exception as e:
                logger.error(f"Error in threat callback: {e}")
        
        logger.warning(f"Threat detected: {description} (Confidence: {confidence:.2f})")
    
    def _get_mitigation_actions(self, threat_type: ThreatType, severity: ThreatSeverity) -> List[str]:
        """Get mitigation actions for threat type"""
        actions = {
            ThreatType.ZERO_CLICK_EXPLOIT: [
                "Immediately isolate the affected device",
                "Update all messaging applications",
                "Run comprehensive malware scan",
                "Check for system integrity violations",
                "Consider factory reset if compromise confirmed"
            ],
            ThreatType.MALICIOUS_LINK: [
                "Do not click or visit the URL",
                "Block the domain in firewall/DNS",
                "Report the URL to security vendors",
                "Scan system for malware",
                "Update browser and security software"
            ],
            ThreatType.APP_TAMPERING: [
                "Reinstall the affected application",
                "Verify application signatures",
                "Check for unauthorized modifications",
                "Run system integrity check",
                "Monitor for further tampering"
            ],
            ThreatType.SUSPICIOUS_BEHAVIOR: [
                "Investigate the suspicious process",
                "Check process legitimacy",
                "Monitor resource usage",
                "Consider terminating if malicious",
                "Update security definitions"
            ]
        }
        
        return actions.get(threat_type, ["Investigate the threat", "Take appropriate action"])
    
    def register_threat_callback(self, callback: Callable[[ThreatDetection], None]) -> None:
        """Register callback for threat detections"""
        self.threat_callbacks.append(callback)
    
    def block_threat(self, threat_id: str) -> bool:
        """Block a detected threat"""
        for detection in self.threat_detections:
            if detection.threat_id == threat_id:
                detection.blocked = True
                logger.info(f"Threat {threat_id} blocked")
                return True
        return False
    
    def mark_false_positive(self, threat_id: str) -> bool:
        """Mark threat as false positive"""
        for detection in self.threat_detections:
            if detection.threat_id == threat_id:
                detection.false_positive = True
                logger.info(f"Threat {threat_id} marked as false positive")
                return True
        return False
    
    def generate_protection_report(self) -> ProtectionReport:
        """Generate comprehensive protection report"""
        logger.info("Generating real-time protection report")
        
        # Calculate metrics
        threats_detected = len(self.threat_detections)
        threats_blocked = sum(1 for t in self.threat_detections if t.blocked)
        apps_verified = len(self.app_integrity_cache)
        links_scanned = len(self.link_scan_cache)
        malicious_links_blocked = sum(1 for l in self.link_scan_cache.values() if l.is_malicious and l.blocked)
        integrity_violations = sum(1 for a in self.app_integrity_cache.values() if not a.is_valid)
        exploit_attempts = sum(1 for t in self.threat_detections if t.threat_type == ThreatType.ZERO_CLICK_EXPLOIT)
        
        # Calculate security score
        security_score = self._calculate_protection_score(
            threats_detected, threats_blocked, integrity_violations, exploit_attempts
        )
        
        # Generate recommendations
        recommendations = self._generate_protection_recommendations(
            threats_detected, integrity_violations, exploit_attempts
        )
        
        from datetime import datetime
        
        report = ProtectionReport(
            timestamp=datetime.now().isoformat(),
            protection_status=ProtectionStatus.ACTIVE if self.protection_active else ProtectionStatus.INACTIVE,
            monitoring_duration=0.0,  # Would track actual monitoring time
            threats_detected=threats_detected,
            threats_blocked=threats_blocked,
            apps_verified=apps_verified,
            links_scanned=links_scanned,
            malicious_links_blocked=malicious_links_blocked,
            integrity_violations=integrity_violations,
            exploit_attempts=exploit_attempts,
            detections=self.threat_detections,
            app_integrity_results=list(self.app_integrity_cache.values()),
            link_scan_results=list(self.link_scan_cache.values()),
            recommendations=recommendations,
            overall_security_score=security_score
        )
        
        logger.info(f"Protection report generated: {security_score:.1f}/100 score")
        return report
    
    def _calculate_protection_score(self, threats_detected: int, threats_blocked: int,
                                  integrity_violations: int, exploit_attempts: int) -> float:
        """Calculate overall protection score"""
        score = 100.0
        
        # Deduct for unblocked threats
        unblocked_threats = threats_detected - threats_blocked
        score -= min(unblocked_threats * 10, 40)
        
        # Deduct for integrity violations
        score -= min(integrity_violations * 15, 30)
        
        # Deduct heavily for exploit attempts
        score -= min(exploit_attempts * 20, 40)
        
        return max(0.0, min(100.0, score))
    
    def _generate_protection_recommendations(self, threats_detected: int,
                                           integrity_violations: int,
                                           exploit_attempts: int) -> List[str]:
        """Generate protection recommendations"""
        recommendations = []
        
        if exploit_attempts > 0:
            recommendations.append(f"🚨 CRITICAL: {exploit_attempts} zero-click exploit attempts detected")
            recommendations.append("Immediately update all messaging and communication apps")
            recommendations.append("Consider device isolation and forensic analysis")
        
        if integrity_violations > 0:
            recommendations.append(f"🔴 {integrity_violations} app integrity violations detected")
            recommendations.append("Reinstall affected applications from trusted sources")
        
        if threats_detected > 0:
            recommendations.append(f"🟠 {threats_detected} total threats detected")
            recommendations.append("Review and investigate all threat detections")
        
        recommendations.extend([
            "Keep all applications updated to latest versions",
            "Enable automatic security updates",
            "Regularly verify application integrity",
            "Use caution when clicking links or opening attachments",
            "Monitor system for unusual behavior"
        ])
        
        return recommendations
    
    def save_report(self, report: ProtectionReport, filename: str) -> None:
        """Save protection report to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(asdict(report), f, indent=2, default=str)
            logger.info(f"Protection report saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")