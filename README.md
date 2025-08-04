# 🕷️ PegaSpy Phase 3

**Advanced Mobile Surveillance Platform**

PegaSpy is a sophisticated mobile surveillance platform that combines zero-click exploits, deep OS control, stealthy self-destruct mechanisms, and a globe-spanning anonymized C2 network into a turnkey solution operated through an intuitive web dashboard.

## ⚠️ LEGAL DISCLAIMER

**THIS SOFTWARE IS FOR AUTHORIZED SECURITY TESTING AND RESEARCH PURPOSES ONLY**

- Only use on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal in most jurisdictions
- Users are solely responsible for compliance with applicable laws
- The developers assume no liability for misuse of this software

## 🎯 Key Features

### Zero-Click Exploits
- **iMessage Exploits**: Advanced iOS messaging vulnerabilities
- **WhatsApp Exploits**: Cross-platform messaging attacks
- **Telegram Exploits**: Secure messaging bypass techniques
- **Stealth Delivery**: Invisible payload deployment
- **Multi-Platform Support**: iOS, Android, Windows, macOS, Linux

### Deep OS Control
- **Kernel-Level Access**: Low-level system manipulation
- **Process Injection**: Stealthy code execution
- **Memory Manipulation**: Runtime modification capabilities
- **System Hook Installation**: API interception
- **Privilege Escalation**: Automated elevation techniques

### Persistence Mechanisms
- **Boot Persistence**: Survive system restarts
- **Service Installation**: Background operation
- **Registry Manipulation**: Windows persistence
- **LaunchAgent/Daemon**: macOS persistence
- **Systemd Services**: Linux persistence
- **Stealth Mode**: Anti-detection techniques

### Globe-Spanning C2 Network
- **Tor Network**: Anonymous communication channels
- **Blockchain C2**: Decentralized command infrastructure
- **CDN Tunneling**: Content delivery network abuse
- **Mesh Networking**: Peer-to-peer resilience
- **Traffic Obfuscation**: Protocol camouflage
- **Node Rotation**: Dynamic infrastructure

### Self-Destruct System
- **Trigger-Based Activation**: Multiple detection methods
- **Evidence Elimination**: Forensic artifact removal
- **Stealth Wiping**: Secure data destruction
- **Emergency Burn**: Instant infrastructure destruction
- **Anti-Analysis**: VM/debugger detection
- **Time-Based Triggers**: Automatic cleanup

### Web Dashboard
- **Real-Time Monitoring**: Live system status
- **Target Management**: Comprehensive victim tracking
- **Exploit Launcher**: Point-and-click operations
- **Campaign Management**: Coordinated attack orchestration
- **Analytics Dashboard**: Performance metrics
- **C2 Network Control**: Infrastructure management

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │   Targets   │ │   Exploits  │ │  Campaigns  │          │
│  └─────────────┘ └─────────────┘ └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Core Engine                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │Zero-Click   │ │ Persistence │ │Self-Destruct│          │
│  │ Exploits    │ │  Manager    │ │   Engine    │          │
│  └─────────────┘ └─────────────┘ └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                C2 Infrastructure                            │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐  │
│  │    Tor    │ │Blockchain │ │    CDN    │ │   Mesh    │  │
│  │  Network  │ │    C2     │ │ Tunneling │ │ Network   │  │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- Administrative/root privileges (for some features)
- Internet connection (for C2 infrastructure)
- Modern web browser (for dashboard)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/pegaspy.git
   cd pegaspy
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the platform:**
   ```bash
   # Edit configuration (optional)
   cp pegaspy_config.json.example pegaspy_config.json
   nano pegaspy_config.json
   ```

4. **Start PegaSpy:**
   ```bash
   python pegaspy.py
   ```

5. **Access the web dashboard:**
   ```
   Open: http://127.0.0.1:5000
   Default password: admin123
   ```

### Command Line Options

```bash
python pegaspy.py [OPTIONS]

Options:
  -c, --config FILE         Configuration file path
  -h, --host HOST          Web dashboard host (default: 127.0.0.1)
  -p, --port PORT          Web dashboard port (default: 5000)
  --debug                  Enable debug mode
  --no-auto-destruct       Disable auto-destruct system
  --no-persistence         Disable persistence mechanisms
  --help                   Show help message
```

## 📋 Configuration

### Basic Configuration

```json
{
  "web_host": "127.0.0.1",
  "web_port": 5000,
  "web_debug": false,
  "web_secret_key": "change_this_in_production",
  
  "tor_enabled": true,
  "blockchain_enabled": true,
  "cdn_enabled": true,
  "mesh_enabled": true,
  
  "auto_destruct_enabled": true,
  "destruct_time_limit": 86400,
  
  "imessage_enabled": true,
  "whatsapp_enabled": true,
  "telegram_enabled": true,
  
  "persistence_enabled": true,
  "stealth_mode": true,
  
  "anti_analysis": true,
  "vm_detection": true,
  "debugger_detection": true
}
```

### Security Settings

- **auto_destruct_enabled**: Enable automatic self-destruct triggers
- **destruct_time_limit**: Time limit before auto-destruct (seconds)
- **anti_analysis**: Enable anti-analysis detection
- **vm_detection**: Detect virtual machine environments
- **debugger_detection**: Detect debugging attempts

## 🎮 Usage Guide

### 1. Dashboard Overview

The main dashboard provides:
- System status overview
- Active targets summary
- Exploit success rates
- C2 network health
- Recent activity logs

### 2. Target Management

**Adding Targets:**
1. Navigate to "Targets" tab
2. Click "Add Target"
3. Enter target information:
   - Phone number or identifier
   - Platform (iOS/Android)
   - OS version
   - Additional metadata

**Target Operations:**
- View target details
- Launch exploits
- Monitor compromise status
- Export target data

### 3. Exploit Operations

**Available Exploits:**
- **iMessage**: iOS messaging vulnerabilities
- **WhatsApp**: Cross-platform messaging
- **Telegram**: Secure messaging bypass

**Launching Exploits:**
1. Select target from list
2. Choose exploit type
3. Configure options:
   - Payload selection
   - Stealth level
   - Persistence method
   - Self-destruct timer
4. Launch exploit
5. Monitor progress in real-time

### 4. Campaign Management

**Creating Campaigns:**
1. Navigate to "Campaigns" tab
2. Click "New Campaign"
3. Configure campaign:
   - Name and description
   - Target selection
   - Exploit sequence
   - Timing parameters
   - Success criteria

**Campaign Operations:**
- Start/pause/resume campaigns
- Monitor progress
- View detailed analytics
- Export campaign reports

### 5. C2 Network Management

**Network Overview:**
- Tor circuit status
- Blockchain channel health
- CDN endpoint availability
- Mesh network topology

**Network Operations:**
- Rotate infrastructure
- Add/remove nodes
- Monitor traffic
- Emergency burn procedures

### 6. Analytics and Reporting

**Available Metrics:**
- Exploit success rates
- Target compromise statistics
- Geographic distribution
- Platform analysis
- Timeline analysis

**Report Generation:**
- Custom date ranges
- Filtered data sets
- Multiple export formats
- Automated scheduling

## 🔧 Advanced Features

### Custom Exploit Development

```python
from zero_click_exploits import BaseExploit, ExploitType

class CustomExploit(BaseExploit):
    def __init__(self):
        super().__init__(
            exploit_id="custom_001",
            exploit_type=ExploitType.CUSTOM,
            name="Custom Exploit",
            description="Custom exploit implementation"
        )
    
    async def execute(self, target, options):
        # Implement custom exploit logic
        pass
```

### Custom Persistence Mechanisms

```python
from persistence import BasePersistence, PersistenceMethod

class CustomPersistence(BasePersistence):
    def __init__(self):
        super().__init__(
            method=PersistenceMethod.CUSTOM,
            name="Custom Persistence"
        )
    
    async def install(self, options):
        # Implement custom persistence
        pass
```

### Custom Triggers

```python
from self_destruct import TriggerRule, TriggerType, TriggerCondition

custom_trigger = TriggerRule(
    trigger_id="custom_trigger",
    trigger_type=TriggerType.CUSTOM,
    condition=TriggerCondition.EQUALS,
    target_value="custom_condition",
    description="Custom trigger condition"
)
```

## 🛡️ Security Considerations

### Operational Security

1. **Network Isolation**: Use dedicated networks for operations
2. **VPN/Tor**: Always use anonymization layers
3. **Burner Infrastructure**: Use disposable resources
4. **Time Limits**: Set appropriate auto-destruct timers
5. **Evidence Management**: Regular cleanup procedures

### Anti-Detection

1. **VM Detection**: Automatic virtual environment detection
2. **Debugger Detection**: Anti-debugging mechanisms
3. **Analysis Detection**: Sandbox and analysis tool detection
4. **Traffic Obfuscation**: Protocol camouflage
5. **Behavioral Mimicry**: Normal traffic patterns

### Emergency Procedures

1. **Manual Burn**: Immediate infrastructure destruction
2. **Evidence Elimination**: Comprehensive artifact removal
3. **Network Isolation**: Automatic disconnection
4. **Data Destruction**: Secure wiping procedures
5. **Alert Systems**: Real-time threat notifications

## 📊 Monitoring and Logging

### Log Levels

- **DEBUG**: Detailed debugging information
- **INFO**: General operational information
- **WARNING**: Warning conditions
- **ERROR**: Error conditions
- **CRITICAL**: Critical security events

### Log Locations

- **Application Logs**: `pegaspy.log`
- **Exploit Logs**: `logs/exploits/`
- **C2 Logs**: `logs/c2/`
- **Security Logs**: `logs/security/`

### Monitoring Metrics

- System resource usage
- Network connectivity
- Exploit success rates
- Target response times
- Security event frequency

## 🔍 Troubleshooting

### Common Issues

**Web Dashboard Not Accessible:**
```bash
# Check if service is running
ps aux | grep pegaspy

# Check port availability
netstat -tlnp | grep 5000

# Check firewall settings
sudo ufw status
```

**C2 Connection Issues:**
```bash
# Test Tor connectivity
curl --socks5 127.0.0.1:9050 https://check.torproject.org

# Check blockchain connectivity
python -c "from web3 import Web3; print(Web3().isConnected())"
```

**Exploit Failures:**
- Verify target platform compatibility
- Check network connectivity
- Review exploit logs
- Validate payload configuration

### Debug Mode

```bash
# Enable debug logging
python pegaspy.py --debug

# Increase log verbosity
export PEGASPY_LOG_LEVEL=DEBUG
```

## 🤝 Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/your-org/pegaspy.git
cd pegaspy

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
pytest tests/

# Code formatting
black .
flake8 .
```

### Code Standards

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write comprehensive docstrings
- Include unit tests for new features
- Maintain security best practices

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Security research community
- Open source contributors
- Ethical hacking community
- Academic researchers

## 📞 Support

For support and questions:

- **Documentation**: [Wiki](https://github.com/your-org/pegaspy/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-org/pegaspy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/pegaspy/discussions)
- **Security**: security@pegaspy.org

---

**Remember: Use responsibly and only on systems you own or have explicit permission to test.**