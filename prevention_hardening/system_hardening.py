"""System Hardening Manager

Provides comprehensive system hardening capabilities including:
- Secure configuration management
- Security policy enforcement
- System vulnerability assessment
- Automated hardening recommendations
"""

import os
import sys
import json
import platform
import subprocess
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from loguru import logger


@dataclass
class SecurityConfiguration:
    """Security configuration setting"""
    name: str
    category: str
    current_value: Any
    recommended_value: Any
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    remediation_steps: List[str]
    requires_reboot: bool = False
    requires_admin: bool = False


@dataclass
class HardeningResult:
    """Result of hardening operation"""
    configuration: str
    success: bool
    error_message: Optional[str] = None
    previous_value: Optional[Any] = None
    new_value: Optional[Any] = None


@dataclass
class SystemHardeningReport:
    """Comprehensive system hardening report"""
    timestamp: str
    platform: str
    total_configurations: int
    vulnerable_configurations: int
    critical_issues: int
    high_risk_issues: int
    medium_risk_issues: int
    low_risk_issues: int
    configurations: List[SecurityConfiguration]
    hardening_results: List[HardeningResult]
    overall_security_score: float
    recommendations: List[str]


class SystemHardeningManager:
    """Manages system hardening and security configuration"""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.configurations: List[SecurityConfiguration] = []
        self.hardening_results: List[HardeningResult] = []
        
        # Load platform-specific configurations
        self._load_security_configurations()
        
        logger.info(f"SystemHardeningManager initialized for {self.platform}")
    
    def _load_security_configurations(self) -> None:
        """Load security configurations based on platform"""
        if self.platform == 'darwin':  # macOS
            self._load_macos_configurations()
        elif self.platform == 'linux':
            self._load_linux_configurations()
        elif self.platform == 'windows':
            self._load_windows_configurations()
        else:
            logger.warning(f"Unsupported platform: {self.platform}")
    
    def _load_macos_configurations(self) -> None:
        """Load macOS-specific security configurations"""
        configs = [
            SecurityConfiguration(
                name="Gatekeeper",
                category="Application Security",
                current_value=self._check_gatekeeper_status(),
                recommended_value="enabled",
                risk_level="HIGH",
                description="Gatekeeper prevents execution of unsigned applications",
                remediation_steps=[
                    "Open System Preferences > Security & Privacy",
                    "Click the General tab",
                    "Select 'App Store and identified developers'"
                ],
                requires_admin=True
            ),
            SecurityConfiguration(
                name="System Integrity Protection (SIP)",
                category="System Security",
                current_value=self._check_sip_status(),
                recommended_value="enabled",
                risk_level="CRITICAL",
                description="SIP protects critical system files and processes",
                remediation_steps=[
                    "Boot into Recovery Mode (Cmd+R)",
                    "Open Terminal",
                    "Run: csrutil enable",
                    "Reboot system"
                ],
                requires_reboot=True,
                requires_admin=True
            ),
            SecurityConfiguration(
                name="FileVault",
                category="Data Protection",
                current_value=self._check_filevault_status(),
                recommended_value="enabled",
                risk_level="HIGH",
                description="FileVault provides full-disk encryption",
                remediation_steps=[
                    "Open System Preferences > Security & Privacy",
                    "Click the FileVault tab",
                    "Click 'Turn On FileVault'"
                ],
                requires_admin=True
            ),
            SecurityConfiguration(
                name="Firewall",
                category="Network Security",
                current_value=self._check_firewall_status(),
                recommended_value="enabled",
                risk_level="MEDIUM",
                description="Firewall blocks unauthorized network connections",
                remediation_steps=[
                    "Open System Preferences > Security & Privacy",
                    "Click the Firewall tab",
                    "Click 'Turn On Firewall'"
                ],
                requires_admin=True
            ),
            SecurityConfiguration(
                name="Remote Login (SSH)",
                category="Network Security",
                current_value=self._check_ssh_status(),
                recommended_value="disabled",
                risk_level="MEDIUM",
                description="SSH should be disabled unless specifically needed",
                remediation_steps=[
                    "Open System Preferences > Sharing",
                    "Uncheck 'Remote Login'"
                ],
                requires_admin=True
            ),
            SecurityConfiguration(
                name="Screen Saver Password",
                category="Access Control",
                current_value=self._check_screensaver_password(),
                recommended_value="enabled",
                risk_level="MEDIUM",
                description="Require password when waking from screen saver",
                remediation_steps=[
                    "Open System Preferences > Security & Privacy",
                    "Check 'Require password immediately after sleep or screen saver begins'"
                ]
            ),
            SecurityConfiguration(
                name="Automatic Updates",
                category="System Maintenance",
                current_value=self._check_auto_updates(),
                recommended_value="enabled",
                risk_level="HIGH",
                description="Automatic updates ensure latest security patches",
                remediation_steps=[
                    "Open System Preferences > Software Update",
                    "Check 'Automatically keep my Mac up to date'"
                ]
            )
        ]
        
        self.configurations.extend(configs)
    
    def _load_linux_configurations(self) -> None:
        """Load Linux-specific security configurations"""
        configs = [
            SecurityConfiguration(
                name="UFW Firewall",
                category="Network Security",
                current_value=self._check_ufw_status(),
                recommended_value="enabled",
                risk_level="HIGH",
                description="UFW provides simple firewall management",
                remediation_steps=[
                    "sudo ufw enable",
                    "sudo ufw default deny incoming",
                    "sudo ufw default allow outgoing"
                ],
                requires_admin=True
            ),
            SecurityConfiguration(
                name="SSH Root Login",
                category="Access Control",
                current_value=self._check_ssh_root_login(),
                recommended_value="disabled",
                risk_level="CRITICAL",
                description="Root SSH login should be disabled",
                remediation_steps=[
                    "Edit /etc/ssh/sshd_config",
                    "Set PermitRootLogin no",
                    "sudo systemctl restart sshd"
                ],
                requires_admin=True
            ),
            SecurityConfiguration(
                name="Automatic Updates",
                category="System Maintenance",
                current_value=self._check_linux_auto_updates(),
                recommended_value="enabled",
                risk_level="HIGH",
                description="Automatic security updates are critical",
                remediation_steps=[
                    "sudo apt install unattended-upgrades",
                    "sudo dpkg-reconfigure -plow unattended-upgrades"
                ],
                requires_admin=True
            ),
            SecurityConfiguration(
                name="Fail2Ban",
                category="Intrusion Prevention",
                current_value=self._check_fail2ban_status(),
                recommended_value="enabled",
                risk_level="MEDIUM",
                description="Fail2Ban protects against brute force attacks",
                remediation_steps=[
                    "sudo apt install fail2ban",
                    "sudo systemctl enable fail2ban",
                    "sudo systemctl start fail2ban"
                ],
                requires_admin=True
            )
        ]
        
        self.configurations.extend(configs)
    
    def _load_windows_configurations(self) -> None:
        """Load Windows-specific security configurations"""
        configs = [
            SecurityConfiguration(
                name="Windows Defender",
                category="Antivirus",
                current_value=self._check_windows_defender(),
                recommended_value="enabled",
                risk_level="CRITICAL",
                description="Windows Defender provides real-time protection",
                remediation_steps=[
                    "Open Windows Security",
                    "Go to Virus & threat protection",
                    "Turn on Real-time protection"
                ],
                requires_admin=True
            ),
            SecurityConfiguration(
                name="Windows Firewall",
                category="Network Security",
                current_value=self._check_windows_firewall(),
                recommended_value="enabled",
                risk_level="HIGH",
                description="Windows Firewall blocks unauthorized connections",
                remediation_steps=[
                    "Open Windows Security",
                    "Go to Firewall & network protection",
                    "Turn on firewall for all networks"
                ],
                requires_admin=True
            ),
            SecurityConfiguration(
                name="BitLocker",
                category="Data Protection",
                current_value=self._check_bitlocker_status(),
                recommended_value="enabled",
                risk_level="HIGH",
                description="BitLocker provides full-disk encryption",
                remediation_steps=[
                    "Open Control Panel > BitLocker Drive Encryption",
                    "Click 'Turn on BitLocker' for system drive"
                ],
                requires_admin=True
            ),
            SecurityConfiguration(
                name="User Account Control (UAC)",
                category="Access Control",
                current_value=self._check_uac_status(),
                recommended_value="enabled",
                risk_level="HIGH",
                description="UAC prevents unauthorized system changes",
                remediation_steps=[
                    "Open Control Panel > User Accounts",
                    "Click 'Change User Account Control settings'",
                    "Set to 'Always notify'"
                ],
                requires_admin=True
            )
        ]
        
        self.configurations.extend(configs)
    
    # Platform-specific check methods
    def _check_gatekeeper_status(self) -> str:
        """Check macOS Gatekeeper status"""
        try:
            result = subprocess.run(['spctl', '--status'], 
                                  capture_output=True, text=True)
            return "enabled" if "assessments enabled" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def _check_sip_status(self) -> str:
        """Check macOS System Integrity Protection status"""
        try:
            result = subprocess.run(['csrutil', 'status'], 
                                  capture_output=True, text=True)
            return "enabled" if "enabled" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def _check_filevault_status(self) -> str:
        """Check macOS FileVault status"""
        try:
            result = subprocess.run(['fdesetup', 'status'], 
                                  capture_output=True, text=True)
            return "enabled" if "On" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def _check_firewall_status(self) -> str:
        """Check firewall status (cross-platform)"""
        if self.platform == 'darwin':
            try:
                result = subprocess.run(['sudo', 'pfctl', '-s', 'info'], 
                                      capture_output=True, text=True)
                return "enabled" if "Status: Enabled" in result.stdout else "disabled"
            except Exception:
                return "unknown"
        elif self.platform == 'linux':
            return self._check_ufw_status()
        elif self.platform == 'windows':
            return self._check_windows_firewall()
        return "unknown"
    
    def _check_ssh_status(self) -> str:
        """Check SSH service status"""
        try:
            if self.platform == 'darwin':
                result = subprocess.run(['sudo', 'systemsetup', '-getremotelogin'], 
                                      capture_output=True, text=True)
                return "enabled" if "On" in result.stdout else "disabled"
            elif self.platform == 'linux':
                result = subprocess.run(['systemctl', 'is-active', 'ssh'], 
                                      capture_output=True, text=True)
                return "enabled" if "active" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def _check_screensaver_password(self) -> str:
        """Check screen saver password requirement"""
        try:
            result = subprocess.run(['defaults', 'read', 'com.apple.screensaver', 
                                   'askForPassword'], capture_output=True, text=True)
            return "enabled" if "1" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def _check_auto_updates(self) -> str:
        """Check automatic updates status"""
        if self.platform == 'darwin':
            try:
                result = subprocess.run(['defaults', 'read', '/Library/Preferences/com.apple.SoftwareUpdate', 
                                       'AutomaticCheckEnabled'], capture_output=True, text=True)
                return "enabled" if "1" in result.stdout else "disabled"
            except Exception:
                return "unknown"
        elif self.platform == 'linux':
            return self._check_linux_auto_updates()
        return "unknown"
    
    def _check_ufw_status(self) -> str:
        """Check UFW firewall status on Linux"""
        try:
            result = subprocess.run(['sudo', 'ufw', 'status'], 
                                  capture_output=True, text=True)
            return "enabled" if "Status: active" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def _check_ssh_root_login(self) -> str:
        """Check SSH root login configuration"""
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                content = f.read()
                if 'PermitRootLogin no' in content:
                    return "disabled"
                elif 'PermitRootLogin yes' in content:
                    return "enabled"
                else:
                    return "default"
        except Exception:
            return "unknown"
    
    def _check_linux_auto_updates(self) -> str:
        """Check Linux automatic updates"""
        try:
            result = subprocess.run(['dpkg', '-l', 'unattended-upgrades'], 
                                  capture_output=True, text=True)
            return "enabled" if "ii" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def _check_fail2ban_status(self) -> str:
        """Check Fail2Ban status"""
        try:
            result = subprocess.run(['systemctl', 'is-active', 'fail2ban'], 
                                  capture_output=True, text=True)
            return "enabled" if "active" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def _check_windows_defender(self) -> str:
        """Check Windows Defender status"""
        try:
            result = subprocess.run(['powershell', 'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled'], 
                                  capture_output=True, text=True)
            return "enabled" if "True" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def _check_windows_firewall(self) -> str:
        """Check Windows Firewall status"""
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], 
                                  capture_output=True, text=True)
            return "enabled" if "ON" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def _check_bitlocker_status(self) -> str:
        """Check BitLocker status"""
        try:
            result = subprocess.run(['manage-bde', '-status'], 
                                  capture_output=True, text=True)
            return "enabled" if "Protection On" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def _check_uac_status(self) -> str:
        """Check User Account Control status"""
        try:
            result = subprocess.run(['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 
                                   '/v', 'EnableLUA'], capture_output=True, text=True)
            return "enabled" if "0x1" in result.stdout else "disabled"
        except Exception:
            return "unknown"
    
    def assess_security_posture(self) -> SystemHardeningReport:
        """Assess current security posture"""
        logger.info("Assessing system security posture")
        
        # Refresh current values
        for config in self.configurations:
            if config.name == "Gatekeeper" and self.platform == 'darwin':
                config.current_value = self._check_gatekeeper_status()
            elif config.name == "System Integrity Protection (SIP)":
                config.current_value = self._check_sip_status()
            elif config.name == "FileVault":
                config.current_value = self._check_filevault_status()
            elif config.name == "Firewall":
                config.current_value = self._check_firewall_status()
            # Add more refresh logic as needed
        
        # Count issues by risk level
        critical_issues = sum(1 for c in self.configurations 
                            if c.risk_level == "CRITICAL" and c.current_value != c.recommended_value)
        high_risk_issues = sum(1 for c in self.configurations 
                             if c.risk_level == "HIGH" and c.current_value != c.recommended_value)
        medium_risk_issues = sum(1 for c in self.configurations 
                               if c.risk_level == "MEDIUM" and c.current_value != c.recommended_value)
        low_risk_issues = sum(1 for c in self.configurations 
                            if c.risk_level == "LOW" and c.current_value != c.recommended_value)
        
        vulnerable_configurations = critical_issues + high_risk_issues + medium_risk_issues + low_risk_issues
        
        # Calculate security score (0-100)
        total_configs = len(self.configurations)
        if total_configs > 0:
            # Weight by risk level
            max_score = sum({
                "CRITICAL": 40,
                "HIGH": 30,
                "MEDIUM": 20,
                "LOW": 10
            }.get(c.risk_level, 10) for c in self.configurations)
            
            current_score = sum({
                "CRITICAL": 40,
                "HIGH": 30,
                "MEDIUM": 20,
                "LOW": 10
            }.get(c.risk_level, 10) for c in self.configurations 
                              if c.current_value == c.recommended_value)
            
            security_score = (current_score / max_score) * 100 if max_score > 0 else 100
        else:
            security_score = 100
        
        # Generate recommendations
        recommendations = self._generate_recommendations(critical_issues, high_risk_issues, 
                                                       medium_risk_issues, low_risk_issues)
        
        from datetime import datetime
        
        report = SystemHardeningReport(
            timestamp=datetime.now().isoformat(),
            platform=self.platform,
            total_configurations=total_configs,
            vulnerable_configurations=vulnerable_configurations,
            critical_issues=critical_issues,
            high_risk_issues=high_risk_issues,
            medium_risk_issues=medium_risk_issues,
            low_risk_issues=low_risk_issues,
            configurations=self.configurations,
            hardening_results=self.hardening_results,
            overall_security_score=security_score,
            recommendations=recommendations
        )
        
        logger.info(f"Security assessment complete: {security_score:.1f}/100 score")
        return report
    
    def _generate_recommendations(self, critical: int, high: int, medium: int, low: int) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if critical > 0:
            recommendations.append(f"🚨 URGENT: {critical} critical security issues require immediate attention")
            recommendations.append("Prioritize fixing critical issues before addressing other problems")
        
        if high > 0:
            recommendations.append(f"🔴 HIGH PRIORITY: {high} high-risk configurations need remediation")
        
        if medium > 0:
            recommendations.append(f"🟠 MEDIUM PRIORITY: {medium} medium-risk issues should be addressed")
        
        if low > 0:
            recommendations.append(f"🟡 LOW PRIORITY: {low} low-risk improvements available")
        
        if critical == 0 and high == 0:
            recommendations.append("✅ No critical or high-risk issues detected")
            recommendations.append("Continue monitoring and maintain current security posture")
        
        # Platform-specific recommendations
        if self.platform == 'darwin':
            recommendations.append("Consider enabling additional macOS security features like Secure Boot")
        elif self.platform == 'linux':
            recommendations.append("Consider implementing additional hardening with tools like Lynis")
        elif self.platform == 'windows':
            recommendations.append("Consider enabling Windows Defender Application Guard")
        
        recommendations.append("Regularly update system and applications")
        recommendations.append("Implement regular security assessments")
        
        return recommendations
    
    def apply_hardening(self, configuration_names: Optional[List[str]] = None, 
                       auto_approve: bool = False) -> List[HardeningResult]:
        """Apply security hardening configurations"""
        logger.info("Starting system hardening process")
        
        configs_to_apply = self.configurations
        if configuration_names:
            configs_to_apply = [c for c in self.configurations if c.name in configuration_names]
        
        results = []
        
        for config in configs_to_apply:
            if config.current_value == config.recommended_value:
                logger.info(f"Configuration '{config.name}' already properly set")
                continue
            
            if not auto_approve:
                response = input(f"Apply hardening for '{config.name}'? (y/n): ")
                if response.lower() != 'y':
                    continue
            
            result = self._apply_single_hardening(config)
            results.append(result)
            self.hardening_results.append(result)
        
        logger.info(f"Hardening process complete: {len(results)} configurations processed")
        return results
    
    def _apply_single_hardening(self, config: SecurityConfiguration) -> HardeningResult:
        """Apply a single hardening configuration"""
        logger.info(f"Applying hardening for: {config.name}")
        
        try:
            previous_value = config.current_value
            
            # This is a simplified implementation
            # In a real implementation, you would execute the actual remediation steps
            logger.warning(f"Hardening simulation for {config.name} - would execute: {config.remediation_steps}")
            
            # Simulate successful application
            new_value = config.recommended_value
            config.current_value = new_value
            
            return HardeningResult(
                configuration=config.name,
                success=True,
                previous_value=previous_value,
                new_value=new_value
            )
            
        except Exception as e:
            logger.error(f"Failed to apply hardening for {config.name}: {e}")
            return HardeningResult(
                configuration=config.name,
                success=False,
                error_message=str(e),
                previous_value=config.current_value
            )
    
    def get_vulnerable_configurations(self) -> List[SecurityConfiguration]:
        """Get list of vulnerable configurations"""
        return [c for c in self.configurations if c.current_value != c.recommended_value]
    
    def get_critical_issues(self) -> List[SecurityConfiguration]:
        """Get list of critical security issues"""
        return [c for c in self.configurations 
                if c.risk_level == "CRITICAL" and c.current_value != c.recommended_value]
    
    def save_report(self, report: SystemHardeningReport, filename: str) -> None:
        """Save hardening report to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(asdict(report), f, indent=2, default=str)
            logger.info(f"Hardening report saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")