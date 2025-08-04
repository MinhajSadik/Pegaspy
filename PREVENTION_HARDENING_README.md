# PegaSpy Prevention & Hardening Tools

## Overview

The Prevention & Hardening Tools module provides comprehensive system hardening and real-time protection capabilities to prevent spyware infections and strengthen device security. This module is part of the larger PegaSpy anti-spyware defense framework.

## 🛡️ Components

### 1. System Hardening Suite
- **SystemHardeningManager**: Manages secure configuration and optimal device settings
- **Features**:
  - Cross-platform security configuration (macOS, Linux, Windows)
  - Security settings audit and scoring
  - Hardening recommendations with priority levels
  - Configuration export/import capabilities
  - Automated security policy enforcement

### 2. App Permission Management
- **AppPermissionManager**: Handles application permission auditing and management
- **Features**:
  - Installed application scanning
  - Permission audit and risk assessment
  - Granular permission controls
  - Risk score calculation based on permission combinations
  - SQLite database integration for tracking

### 3. Network Security Monitoring
- **NetworkSecurityMonitor**: Provides real-time network security monitoring
- **Features**:
  - Network connection scanning and analysis
  - Threat assessment for connections
  - VPN status monitoring and management
  - Firewall rule management
  - DNS security monitoring
  - IP blocking/unblocking capabilities

### 4. Real-time Protection Engine
- **RealTimeProtectionEngine**: Active threat prevention and monitoring
- **Features**:
  - Zero-click exploit detection
  - Malicious link scanning
  - App integrity verification
  - Real-time process monitoring
  - File system change detection
  - Network behavior analysis

### 5. Zero-click Exploit Detection
- **ZeroClickExploitDetector**: Advanced exploit detection system
- **Features**:
  - Predefined exploit signatures (Pegasus, NSO Group patterns)
  - Behavioral pattern analysis
  - Process behavior monitoring
  - Memory analysis capabilities
  - Automatic mitigation actions
  - YARA rules support

### 6. Malicious Link Scanner
- **MaliciousLinkScanner**: Comprehensive URL analysis and threat detection
- **Features**:
  - Multi-engine URL scanning
  - Domain reputation analysis
  - Phishing detection patterns
  - URL shortener analysis
  - Threat categorization
  - Batch scanning capabilities

### 7. App Integrity Verification
- **AppIntegrityVerifier**: Application integrity monitoring and tamper detection
- **Features**:
  - Binary signature verification
  - Code signing validation
  - Runtime integrity checks
  - File system monitoring
  - Baseline creation and comparison
  - Anti-tampering mechanisms

## 🚀 Installation

### Prerequisites
```bash
# Install required dependencies
pip3 install -r requirements.txt
```

### Required Dependencies
- `loguru>=0.7.0` - Advanced logging
- `psutil>=5.9.5` - System and process utilities
- `requests>=2.31.0` - HTTP library
- `pyyaml>=6.0` - YAML configuration
- `cryptography>=41.0.0` - Cryptographic operations
- `watchdog>=3.0.0` - File system monitoring
- `scapy>=2.5.0` - Network packet manipulation

### Platform-specific Dependencies
- **macOS**: `pyobjc-framework-*` packages for system integration
- **Windows**: `pywin32`, `wmi` for Windows-specific features
- **Linux**: Standard Python libraries (most features work out-of-box)

## 📖 Usage

### Basic Usage

```python
from prevention_hardening import (
    SystemHardeningManager,
    AppPermissionManager,
    NetworkSecurityMonitor,
    RealTimeProtectionEngine,
    ZeroClickExploitDetector,
    MaliciousLinkScanner,
    AppIntegrityVerifier
)

# System Hardening
hardening_manager = SystemHardeningManager()
report = hardening_manager.check_security_settings()
print(f"Security Score: {report.overall_score}/100")

# App Permission Management
permission_manager = AppPermissionManager()
apps = permission_manager.scan_installed_apps()
print(f"Found {len(apps)} applications")

# Network Security Monitoring
network_monitor = NetworkSecurityMonitor()
connections = network_monitor.scan_network_connections()
print(f"Active connections: {len(connections)}")

# Real-time Protection
protection_engine = RealTimeProtectionEngine()
protection_engine.start_protection()
# ... protection runs in background
protection_engine.stop_protection()

# Link Scanning
link_scanner = MaliciousLinkScanner()
result = link_scanner.scan_url("https://example.com")
print(f"URL verdict: {result.overall_verdict}")

# App Integrity
integrity_verifier = AppIntegrityVerifier()
baseline = integrity_verifier.create_baseline("/path/to/app", "AppName", "1.0")
report = integrity_verifier.verify_integrity("/path/to/app")
print(f"Integrity: {report.overall_status.value}")
```

### Running Tests

```bash
# Run comprehensive test suite
python3 test_prevention_hardening.py

# Run simple demo
python3 simple_demo.py
```

### Configuration

The framework supports configuration through YAML files:

```yaml
# config/prevention_hardening.yaml
system_hardening:
  auto_apply: false
  backup_configs: true
  
real_time_protection:
  enable_exploit_detection: true
  enable_link_scanning: true
  enable_integrity_monitoring: true
  
network_security:
  monitor_all_connections: true
  block_suspicious_ips: true
  vpn_required: false
```

## 🔧 Advanced Features

### Custom Exploit Signatures

```python
# Add custom exploit signature
exploit_detector = ZeroClickExploitDetector()
custom_signature = {
    'name': 'Custom Exploit',
    'description': 'Custom spyware pattern',
    'indicators': ['suspicious_process_name', 'unusual_network_activity'],
    'severity': 'high'
}
exploit_detector.add_custom_signature(custom_signature)
```

### Batch URL Scanning

```python
# Scan multiple URLs
link_scanner = MaliciousLinkScanner()
urls = ['https://site1.com', 'https://site2.com', 'https://site3.com']
reports = link_scanner.scan_multiple_urls(urls)
for report in reports:
    print(f"{report.url}: {report.overall_verdict}")
```

### Real-time Monitoring

```python
# Set up real-time protection with custom callbacks
def threat_detected_callback(threat_info):
    print(f"Threat detected: {threat_info}")
    # Custom response logic here

protection_engine = RealTimeProtectionEngine()
protection_engine.set_threat_callback(threat_detected_callback)
protection_engine.start_protection()
```

## 📊 Test Results

The framework has been tested with the following results:

- **Test Suite**: 25/29 tests passed (86.2% success rate)
- **Core Components**: All major components functional
- **Platform Support**: Tested on macOS, partial Linux/Windows support
- **Performance**: Efficient resource usage with configurable monitoring intervals

### Working Components ✅
- Malicious Link Scanner
- App Integrity Verifier
- Zero-click Exploit Detection (partial)
- System Hardening Manager (basic functionality)

### Components Needing Attention ⚠️
- App Permission Manager (platform-specific implementations)
- Network Security Monitor (advanced features)
- Real-time Protection Engine (some edge cases)

## 🔒 Security Considerations

### Privacy by Design
- No data collection without explicit consent
- Local processing of sensitive information
- Encrypted storage of security configurations
- Minimal network communication

### Performance Impact
- Configurable monitoring intervals
- Efficient resource usage
- Background processing for non-critical tasks
- Graceful degradation on resource-constrained systems

### False Positive Mitigation
- Multiple detection engines for cross-validation
- Confidence scoring for all detections
- User-configurable sensitivity levels
- Whitelist/blacklist management

## 🛠️ Development

### Architecture

The Prevention & Hardening Tools follow a modular architecture:

```
prevention_hardening/
├── __init__.py              # Module initialization
├── system_hardening.py      # System configuration management
├── app_permissions.py       # Application permission management
├── network_security.py      # Network monitoring and security
├── realtime_protection.py   # Real-time threat protection
├── exploit_detection.py     # Zero-click exploit detection
├── link_scanner.py          # Malicious link analysis
└── app_integrity.py         # Application integrity verification
```

### Adding New Components

1. Create new module file in `prevention_hardening/`
2. Implement required interfaces and data structures
3. Add imports to `__init__.py`
4. Create corresponding tests
5. Update documentation

### Contributing

1. Fork the repository
2. Create feature branch
3. Implement changes with tests
4. Submit pull request
5. Ensure all tests pass

## 📝 Logging

The framework uses structured logging with Loguru:

```python
from loguru import logger

# Configure logging
logger.add("prevention_hardening.log", 
          format="{time} | {level} | {module}:{function}:{line} - {message}",
          level="INFO")
```

## 🚨 Known Issues

1. **YARA Integration**: Optional dependency, some advanced detection features disabled without it
2. **Platform Compatibility**: Some features are macOS-specific, Windows/Linux implementations partial
3. **Performance**: Real-time monitoring can be resource-intensive on older systems
4. **False Positives**: Some legitimate applications may trigger security warnings

## 🔮 Future Enhancements

- [ ] Machine learning-based threat detection
- [ ] Cloud-based threat intelligence integration
- [ ] Mobile device support (iOS/Android)
- [ ] Web-based management dashboard
- [ ] API for third-party integrations
- [ ] Automated response and remediation
- [ ] Enhanced reporting and analytics

## 📞 Support

For issues, questions, or contributions:

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Comprehensive guides and API reference
- **Community**: Join discussions and share experiences
- **Security**: Responsible disclosure for security vulnerabilities

## 📄 License

This project is part of the PegaSpy framework and follows the same licensing terms. See the main project LICENSE file for details.

---

**Note**: This is a security-focused framework. Always test in a safe environment before deploying to production systems. The framework is designed to complement, not replace, existing security solutions.