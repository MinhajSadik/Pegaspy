# PegaSpy Usage Guide

## Quick Start

### 1. Setup Environment

```bash
# Navigate to the project directory
cd /path/to/Pegaspy

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Security Scans

#### Quick Scan (Recommended for regular checks)
```bash
python main.py --quick
```

#### Comprehensive Scan (Deep analysis)
```bash
python main.py --comprehensive
```

#### Custom Comprehensive Scan
```bash
# Custom monitoring durations
python main.py --comprehensive --network-time 600 --behavioral-time 900

# Custom output directory
python main.py --quick --output-dir /path/to/custom/reports

# Verbose logging
python main.py --quick --verbose
```

## Understanding Scan Results

### Threat Levels
- **🟢 CLEAN**: No threats detected
- **🟡 LOW**: Minor issues detected
- **🟠 MEDIUM**: Investigate detected issues
- **🔴 HIGH**: Urgent investigation required
- **🚨 CRITICAL**: Immediate action required

### Scan Components

#### 1. Process Scan (Mobile Scanner)
- Monitors running processes
- Detects suspicious process behavior
- Analyzes network connections
- Checks for file modifications

#### 2. File Integrity Check
- Monitors critical system files
- Detects unauthorized modifications
- Tracks new/deleted files
- Identifies suspicious file changes

#### 3. Network Analysis (Comprehensive only)
- Monitors network traffic
- Detects suspicious connections
- Analyzes DNS queries
- Identifies potential data exfiltration

#### 4. Behavioral Analysis (Comprehensive only)
- Monitors process behaviors
- Detects keylogger patterns
- Identifies spyware indicators
- Analyzes resource usage patterns

## Report Files

After each scan, reports are saved to the `reports/` directory:

- `pegaspy_summary_YYYYMMDD_HHMMSS.json` - Overall scan summary
- `mobile_scan_YYYYMMDD_HHMMSS.json` - Detailed process analysis
- `file_integrity_YYYYMMDD_HHMMSS.json` - File system changes
- `network_analysis_YYYYMMDD_HHMMSS.json` - Network traffic analysis
- `behavioral_analysis_YYYYMMDD_HHMMSS.json` - Behavioral patterns
- `pegaspy.log` - Detailed execution logs

## Testing the Framework

```bash
# Run the test suite
python test_framework.py
```

## Individual Module Usage

### Mobile Device Scanner
```python
from detection_analysis.mobile_scanner import MobileDeviceScanner

scanner = MobileDeviceScanner()
result = scanner.perform_full_scan()
print(f"Threat level: {result.threat_level}")
```

### File Integrity Checker
```python
from detection_analysis.file_integrity import FileIntegrityChecker

checker = FileIntegrityChecker()
report = checker.generate_integrity_report(['/path/to/monitor'])
print(f"Changes detected: {report.changes_detected}")
```

### Network Traffic Analyzer
```python
from detection_analysis.network_analyzer import NetworkTrafficAnalyzer

analyzer = NetworkTrafficAnalyzer()
analyzer.start_monitoring(duration=300)  # 5 minutes
report = analyzer.generate_report()
print(f"Suspicious flows: {report['suspicious_flows']}")
```

### Behavioral Analysis Engine
```python
from detection_analysis.behavioral_engine import BehavioralAnalysisEngine

engine = BehavioralAnalysisEngine()
engine.start_monitoring()
# ... wait for monitoring period ...
engine.stop_monitoring()
report = engine.generate_behavioral_report()
print(f"High-risk processes: {len(report.high_risk_processes)}")
```

## Security Recommendations

### Based on Scan Results

#### CRITICAL Threat Level
- **Immediately disconnect** from the network
- Run full system remediation
- Consider professional incident response
- Backup critical data to isolated storage

#### HIGH Threat Level
- Isolate the system from network
- Run additional security scans
- Review all detected indicators
- Consider reimaging the system

#### MEDIUM Threat Level
- Investigate all detected issues
- Monitor system closely
- Update security software
- Review system logs

#### LOW Threat Level
- Address minor issues found
- Continue regular monitoring
- Update system and software
- Review security practices

### General Security Practices

1. **Regular Scanning**: Run quick scans daily, comprehensive scans weekly
2. **Keep Updated**: Regularly update the framework and dependencies
3. **Monitor Logs**: Review generated logs for patterns
4. **Baseline Establishment**: Run scans on clean systems to establish baselines
5. **Incident Response**: Have a plan for responding to detected threats

## Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Some features require elevated privileges
sudo python main.py --quick
```

#### Network Monitoring Issues
- Ensure you have permission to capture network traffic
- On macOS, you may need to run with sudo for network analysis
- Some corporate networks may block packet capture

#### Missing Dependencies
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

#### Platform-Specific Limitations
- Some features may not work on all operating systems
- Mobile device analysis is limited on desktop systems
- Network analysis capabilities vary by platform

### Getting Help

1. Check the logs in `reports/pegaspy.log`
2. Run with `--verbose` flag for detailed output
3. Use the test framework to verify installation
4. Review the error messages for specific guidance

## Advanced Configuration

### Customizing Detection Rules

You can modify the detection patterns in each module:

- **Suspicious processes**: Edit patterns in `mobile_scanner.py`
- **File monitoring**: Modify paths in `file_integrity.py`
- **Network rules**: Update IP lists in `network_analyzer.py`
- **Behavioral patterns**: Adjust thresholds in `behavioral_engine.py`

### Integration with Other Tools

The framework can be integrated with:
- SIEM systems (via JSON reports)
- Monitoring dashboards (via Flask web interface)
- Automated response systems (via API endpoints)
- Threat intelligence feeds (via custom modules)

---

**Remember**: This framework is designed for legitimate cybersecurity defense purposes. Always ensure you have proper authorization before running security scans on any system.