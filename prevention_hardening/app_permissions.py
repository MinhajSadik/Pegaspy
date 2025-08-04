"""App Permission Manager

Provides comprehensive application permission management including:
- Permission auditing and analysis
- Granular permission controls
- Risk assessment for app permissions
- Permission policy enforcement
"""

import os
import json
import sqlite3
import subprocess
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum
from loguru import logger


class PermissionType(Enum):
    """Types of permissions"""
    CAMERA = "camera"
    MICROPHONE = "microphone"
    LOCATION = "location"
    CONTACTS = "contacts"
    CALENDAR = "calendar"
    PHOTOS = "photos"
    REMINDERS = "reminders"
    FULL_DISK_ACCESS = "full_disk_access"
    ACCESSIBILITY = "accessibility"
    SCREEN_RECORDING = "screen_recording"
    AUTOMATION = "automation"
    NETWORK = "network"
    BLUETOOTH = "bluetooth"
    NOTIFICATIONS = "notifications"
    BACKGROUND_APP_REFRESH = "background_app_refresh"
    CELLULAR_DATA = "cellular_data"
    STORAGE = "storage"
    SMS = "sms"
    PHONE = "phone"
    DEVICE_ADMIN = "device_admin"
    SYSTEM_ALERT_WINDOW = "system_alert_window"
    INSTALL_UNKNOWN_APPS = "install_unknown_apps"


class PermissionStatus(Enum):
    """Permission status"""
    GRANTED = "granted"
    DENIED = "denied"
    NOT_DETERMINED = "not_determined"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk levels for permissions"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AppPermission:
    """Individual app permission"""
    app_id: str
    app_name: str
    permission_type: PermissionType
    status: PermissionStatus
    risk_level: RiskLevel
    description: str
    last_used: Optional[str] = None
    usage_frequency: int = 0
    is_necessary: bool = True
    justification: str = ""


@dataclass
class AppInfo:
    """Application information"""
    app_id: str
    app_name: str
    bundle_id: str
    version: str
    developer: str
    install_date: Optional[str] = None
    last_updated: Optional[str] = None
    app_store_app: bool = False
    signed: bool = False
    permissions: List[AppPermission] = None
    risk_score: float = 0.0
    category: str = "unknown"

    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []


@dataclass
class PermissionAuditReport:
    """Permission audit report"""
    timestamp: str
    total_apps: int
    total_permissions: int
    high_risk_permissions: int
    critical_permissions: int
    unnecessary_permissions: int
    apps: List[AppInfo]
    recommendations: List[str]
    policy_violations: List[str]
    overall_risk_score: float


class AppPermissionManager:
    """Manages application permissions and security policies"""
    
    def __init__(self):
        self.apps: Dict[str, AppInfo] = {}
        self.permission_policies: Dict[PermissionType, Dict[str, Any]] = {}
        self.db_path = "app_permissions.db"
        
        # Initialize permission risk mappings
        self._init_permission_risks()
        
        # Initialize database
        self._init_database()
        
        logger.info("AppPermissionManager initialized")
    
    def _init_permission_risks(self) -> None:
        """Initialize permission risk levels"""
        self.permission_risks = {
            PermissionType.CAMERA: RiskLevel.HIGH,
            PermissionType.MICROPHONE: RiskLevel.HIGH,
            PermissionType.LOCATION: RiskLevel.HIGH,
            PermissionType.CONTACTS: RiskLevel.MEDIUM,
            PermissionType.CALENDAR: RiskLevel.MEDIUM,
            PermissionType.PHOTOS: RiskLevel.MEDIUM,
            PermissionType.REMINDERS: RiskLevel.LOW,
            PermissionType.FULL_DISK_ACCESS: RiskLevel.CRITICAL,
            PermissionType.ACCESSIBILITY: RiskLevel.CRITICAL,
            PermissionType.SCREEN_RECORDING: RiskLevel.CRITICAL,
            PermissionType.AUTOMATION: RiskLevel.HIGH,
            PermissionType.NETWORK: RiskLevel.MEDIUM,
            PermissionType.BLUETOOTH: RiskLevel.MEDIUM,
            PermissionType.NOTIFICATIONS: RiskLevel.LOW,
            PermissionType.BACKGROUND_APP_REFRESH: RiskLevel.MEDIUM,
            PermissionType.CELLULAR_DATA: RiskLevel.LOW,
            PermissionType.STORAGE: RiskLevel.MEDIUM,
            PermissionType.SMS: RiskLevel.HIGH,
            PermissionType.PHONE: RiskLevel.HIGH,
            PermissionType.DEVICE_ADMIN: RiskLevel.CRITICAL,
            PermissionType.SYSTEM_ALERT_WINDOW: RiskLevel.HIGH,
            PermissionType.INSTALL_UNKNOWN_APPS: RiskLevel.CRITICAL
        }
    
    def _init_database(self) -> None:
        """Initialize SQLite database for permission tracking"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS apps (
                    app_id TEXT PRIMARY KEY,
                    app_name TEXT,
                    bundle_id TEXT,
                    version TEXT,
                    developer TEXT,
                    install_date TEXT,
                    last_updated TEXT,
                    app_store_app BOOLEAN,
                    signed BOOLEAN,
                    risk_score REAL,
                    category TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id TEXT,
                    permission_type TEXT,
                    status TEXT,
                    risk_level TEXT,
                    description TEXT,
                    last_used TEXT,
                    usage_frequency INTEGER,
                    is_necessary BOOLEAN,
                    justification TEXT,
                    FOREIGN KEY (app_id) REFERENCES apps (app_id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS permission_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id TEXT,
                    permission_type TEXT,
                    old_status TEXT,
                    new_status TEXT,
                    timestamp TEXT,
                    reason TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
    
    def scan_installed_apps(self) -> List[AppInfo]:
        """Scan for installed applications and their permissions"""
        logger.info("Scanning installed applications")
        
        apps = []
        
        try:
            # macOS app scanning
            if os.name == 'posix' and 'darwin' in os.uname().sysname.lower():
                apps.extend(self._scan_macos_apps())
            
            # Linux app scanning
            elif os.name == 'posix':
                apps.extend(self._scan_linux_apps())
            
            # Windows app scanning
            elif os.name == 'nt':
                apps.extend(self._scan_windows_apps())
            
            # Update internal storage
            for app in apps:
                self.apps[app.app_id] = app
                self._save_app_to_db(app)
            
            logger.info(f"Found {len(apps)} installed applications")
            
        except Exception as e:
            logger.error(f"Error scanning apps: {e}")
        
        return apps
    
    def _scan_macos_apps(self) -> List[AppInfo]:
        """Scan macOS applications"""
        apps = []
        
        # Scan Applications folder
        app_dirs = [
            "/Applications",
            "/System/Applications",
            os.path.expanduser("~/Applications")
        ]
        
        for app_dir in app_dirs:
            if os.path.exists(app_dir):
                for item in os.listdir(app_dir):
                    if item.endswith('.app'):
                        app_path = os.path.join(app_dir, item)
                        app_info = self._get_macos_app_info(app_path)
                        if app_info:
                            apps.append(app_info)
        
        return apps
    
    def _get_macos_app_info(self, app_path: str) -> Optional[AppInfo]:
        """Get macOS app information and permissions"""
        try:
            # Get app bundle info
            info_plist = os.path.join(app_path, "Contents", "Info.plist")
            if not os.path.exists(info_plist):
                return None
            
            # Parse plist for basic info
            result = subprocess.run(['plutil', '-convert', 'json', '-o', '-', info_plist],
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                return None
            
            plist_data = json.loads(result.stdout)
            
            app_name = plist_data.get('CFBundleDisplayName', 
                                    plist_data.get('CFBundleName', 
                                                 os.path.basename(app_path).replace('.app', '')))
            bundle_id = plist_data.get('CFBundleIdentifier', '')
            version = plist_data.get('CFBundleShortVersionString', 
                                   plist_data.get('CFBundleVersion', 'unknown'))
            
            app_info = AppInfo(
                app_id=bundle_id or app_name,
                app_name=app_name,
                bundle_id=bundle_id,
                version=version,
                developer=plist_data.get('CFBundleExecutable', 'unknown'),
                app_store_app=self._is_app_store_app(app_path),
                signed=self._is_app_signed(app_path)
            )
            
            # Get permissions
            app_info.permissions = self._get_macos_app_permissions(bundle_id, app_name)
            app_info.risk_score = self._calculate_risk_score(app_info)
            
            return app_info
            
        except Exception as e:
            logger.error(f"Error getting app info for {app_path}: {e}")
            return None
    
    def _get_macos_app_permissions(self, bundle_id: str, app_name: str) -> List[AppPermission]:
        """Get macOS app permissions using TCC database and system preferences"""
        permissions = []
        
        try:
            # Check TCC (Transparency, Consent, and Control) database
            tcc_permissions = self._check_tcc_permissions(bundle_id)
            permissions.extend(tcc_permissions)
            
            # Check system preferences for additional permissions
            system_permissions = self._check_system_permissions(bundle_id, app_name)
            permissions.extend(system_permissions)
            
        except Exception as e:
            logger.error(f"Error getting permissions for {bundle_id}: {e}")
        
        return permissions
    
    def _check_tcc_permissions(self, bundle_id: str) -> List[AppPermission]:
        """Check TCC database for privacy permissions"""
        permissions = []
        
        try:
            # TCC database locations
            tcc_paths = [
                "/Library/Application Support/com.apple.TCC/TCC.db",
                os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")
            ]
            
            for tcc_path in tcc_paths:
                if os.path.exists(tcc_path):
                    conn = sqlite3.connect(tcc_path)
                    cursor = conn.cursor()
                    
                    cursor.execute(
                        "SELECT service, allowed FROM access WHERE client = ?",
                        (bundle_id,)
                    )
                    
                    for service, allowed in cursor.fetchall():
                        permission_type = self._map_tcc_service_to_permission(service)
                        if permission_type:
                            status = PermissionStatus.GRANTED if allowed else PermissionStatus.DENIED
                            
                            permission = AppPermission(
                                app_id=bundle_id,
                                app_name="",  # Will be filled by caller
                                permission_type=permission_type,
                                status=status,
                                risk_level=self.permission_risks.get(permission_type, RiskLevel.MEDIUM),
                                description=f"Access to {permission_type.value}"
                            )
                            permissions.append(permission)
                    
                    conn.close()
                    
        except Exception as e:
            logger.error(f"Error checking TCC permissions: {e}")
        
        return permissions
    
    def _map_tcc_service_to_permission(self, service: str) -> Optional[PermissionType]:
        """Map TCC service names to permission types"""
        mapping = {
            'kTCCServiceCamera': PermissionType.CAMERA,
            'kTCCServiceMicrophone': PermissionType.MICROPHONE,
            'kTCCServiceLocation': PermissionType.LOCATION,
            'kTCCServiceContacts': PermissionType.CONTACTS,
            'kTCCServiceCalendar': PermissionType.CALENDAR,
            'kTCCServicePhotos': PermissionType.PHOTOS,
            'kTCCServiceReminders': PermissionType.REMINDERS,
            'kTCCServiceSystemPolicyAllFiles': PermissionType.FULL_DISK_ACCESS,
            'kTCCServiceAccessibility': PermissionType.ACCESSIBILITY,
            'kTCCServiceScreenCapture': PermissionType.SCREEN_RECORDING,
            'kTCCServiceSystemPolicyDesktopFolder': PermissionType.STORAGE,
        }
        return mapping.get(service)
    
    def _check_system_permissions(self, bundle_id: str, app_name: str) -> List[AppPermission]:
        """Check system-level permissions"""
        permissions = []
        
        # This would involve checking various system configurations
        # For now, return empty list as implementation would be complex
        
        return permissions
    
    def _scan_linux_apps(self) -> List[AppInfo]:
        """Scan Linux applications (simplified)"""
        apps = []
        
        try:
            # Check installed packages
            result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines[5:]:  # Skip header lines
                    if line.startswith('ii'):
                        parts = line.split()
                        if len(parts) >= 3:
                            package_name = parts[1]
                            version = parts[2]
                            
                            app_info = AppInfo(
                                app_id=package_name,
                                app_name=package_name,
                                bundle_id=package_name,
                                version=version,
                                developer="unknown",
                                category="system"
                            )
                            
                            apps.append(app_info)
                            
        except Exception as e:
            logger.error(f"Error scanning Linux apps: {e}")
        
        return apps
    
    def _scan_windows_apps(self) -> List[AppInfo]:
        """Scan Windows applications (simplified)"""
        apps = []
        
        try:
            # Use PowerShell to get installed apps
            result = subprocess.run([
                'powershell', 
                'Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines[3:]:  # Skip header lines
                    if line.strip():
                        # Parse PowerShell output (simplified)
                        app_info = AppInfo(
                            app_id=line.strip(),
                            app_name=line.strip(),
                            bundle_id=line.strip(),
                            version="unknown",
                            developer="unknown",
                            category="application"
                        )
                        apps.append(app_info)
                        
        except Exception as e:
            logger.error(f"Error scanning Windows apps: {e}")
        
        return apps
    
    def _is_app_store_app(self, app_path: str) -> bool:
        """Check if app is from App Store"""
        try:
            receipt_path = os.path.join(app_path, "Contents", "_MASReceipt", "receipt")
            return os.path.exists(receipt_path)
        except Exception:
            return False
    
    def _is_app_signed(self, app_path: str) -> bool:
        """Check if app is code signed"""
        try:
            result = subprocess.run(['codesign', '-v', app_path], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def _calculate_risk_score(self, app_info: AppInfo) -> float:
        """Calculate risk score for an application"""
        score = 0.0
        
        # Base score factors
        if not app_info.app_store_app:
            score += 20  # Non-App Store apps are riskier
        
        if not app_info.signed:
            score += 30  # Unsigned apps are very risky
        
        # Permission-based scoring
        for permission in app_info.permissions:
            if permission.status == PermissionStatus.GRANTED:
                risk_points = {
                    RiskLevel.LOW: 5,
                    RiskLevel.MEDIUM: 15,
                    RiskLevel.HIGH: 25,
                    RiskLevel.CRITICAL: 40
                }.get(permission.risk_level, 10)
                
                score += risk_points
                
                # Extra penalty for unnecessary permissions
                if not permission.is_necessary:
                    score += risk_points * 0.5
        
        # Normalize to 0-100 scale
        return min(score, 100.0)
    
    def audit_permissions(self) -> PermissionAuditReport:
        """Perform comprehensive permission audit"""
        logger.info("Starting permission audit")
        
        # Ensure we have current app data
        if not self.apps:
            self.scan_installed_apps()
        
        total_apps = len(self.apps)
        total_permissions = sum(len(app.permissions) for app in self.apps.values())
        
        high_risk_permissions = 0
        critical_permissions = 0
        unnecessary_permissions = 0
        
        for app in self.apps.values():
            for permission in app.permissions:
                if permission.status == PermissionStatus.GRANTED:
                    if permission.risk_level == RiskLevel.HIGH:
                        high_risk_permissions += 1
                    elif permission.risk_level == RiskLevel.CRITICAL:
                        critical_permissions += 1
                    
                    if not permission.is_necessary:
                        unnecessary_permissions += 1
        
        # Calculate overall risk score
        if total_apps > 0:
            overall_risk_score = sum(app.risk_score for app in self.apps.values()) / total_apps
        else:
            overall_risk_score = 0.0
        
        # Generate recommendations
        recommendations = self._generate_audit_recommendations(
            critical_permissions, high_risk_permissions, unnecessary_permissions
        )
        
        # Check policy violations
        policy_violations = self._check_policy_violations()
        
        from datetime import datetime
        
        report = PermissionAuditReport(
            timestamp=datetime.now().isoformat(),
            total_apps=total_apps,
            total_permissions=total_permissions,
            high_risk_permissions=high_risk_permissions,
            critical_permissions=critical_permissions,
            unnecessary_permissions=unnecessary_permissions,
            apps=list(self.apps.values()),
            recommendations=recommendations,
            policy_violations=policy_violations,
            overall_risk_score=overall_risk_score
        )
        
        logger.info(f"Permission audit complete: {total_apps} apps, {total_permissions} permissions")
        return report
    
    def _generate_audit_recommendations(self, critical: int, high_risk: int, unnecessary: int) -> List[str]:
        """Generate audit recommendations"""
        recommendations = []
        
        if critical > 0:
            recommendations.append(f"🚨 CRITICAL: {critical} critical permissions require immediate review")
            recommendations.append("Review and revoke critical permissions for non-essential apps")
        
        if high_risk > 0:
            recommendations.append(f"🔴 HIGH RISK: {high_risk} high-risk permissions need attention")
            recommendations.append("Audit high-risk permissions and ensure they're necessary")
        
        if unnecessary > 0:
            recommendations.append(f"🟠 OPTIMIZATION: {unnecessary} unnecessary permissions can be revoked")
            recommendations.append("Revoke permissions that apps don't actually need")
        
        recommendations.extend([
            "Regularly review app permissions",
            "Only install apps from trusted sources",
            "Keep apps updated to latest versions",
            "Use principle of least privilege",
            "Monitor permission usage patterns"
        ])
        
        return recommendations
    
    def _check_policy_violations(self) -> List[str]:
        """Check for policy violations"""
        violations = []
        
        for app in self.apps.values():
            # Check for unsigned apps with sensitive permissions
            if not app.signed:
                sensitive_perms = [p for p in app.permissions 
                                 if p.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] 
                                 and p.status == PermissionStatus.GRANTED]
                if sensitive_perms:
                    violations.append(f"Unsigned app '{app.app_name}' has sensitive permissions")
            
            # Check for excessive permissions
            if app.risk_score > 80:
                violations.append(f"App '{app.app_name}' has excessive permissions (risk score: {app.risk_score:.1f})")
        
        return violations
    
    def revoke_permission(self, app_id: str, permission_type: PermissionType, reason: str = "") -> bool:
        """Revoke a specific permission for an app"""
        logger.info(f"Revoking {permission_type.value} permission for {app_id}")
        
        try:
            # This would involve platform-specific permission revocation
            # For now, simulate the operation
            
            if app_id in self.apps:
                app = self.apps[app_id]
                for permission in app.permissions:
                    if permission.permission_type == permission_type:
                        old_status = permission.status
                        permission.status = PermissionStatus.DENIED
                        
                        # Log the change
                        self._log_permission_change(app_id, permission_type, old_status, 
                                                   PermissionStatus.DENIED, reason)
                        
                        # Update database
                        self._update_permission_in_db(app_id, permission)
                        
                        logger.info(f"Permission {permission_type.value} revoked for {app_id}")
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to revoke permission: {e}")
            return False
    
    def grant_permission(self, app_id: str, permission_type: PermissionType, reason: str = "") -> bool:
        """Grant a specific permission to an app"""
        logger.info(f"Granting {permission_type.value} permission to {app_id}")
        
        try:
            # This would involve platform-specific permission granting
            # For now, simulate the operation
            
            if app_id in self.apps:
                app = self.apps[app_id]
                for permission in app.permissions:
                    if permission.permission_type == permission_type:
                        old_status = permission.status
                        permission.status = PermissionStatus.GRANTED
                        
                        # Log the change
                        self._log_permission_change(app_id, permission_type, old_status, 
                                                   PermissionStatus.GRANTED, reason)
                        
                        # Update database
                        self._update_permission_in_db(app_id, permission)
                        
                        logger.info(f"Permission {permission_type.value} granted to {app_id}")
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to grant permission: {e}")
            return False
    
    def _log_permission_change(self, app_id: str, permission_type: PermissionType, 
                              old_status: PermissionStatus, new_status: PermissionStatus, 
                              reason: str) -> None:
        """Log permission changes to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            from datetime import datetime
            
            cursor.execute(
                "INSERT INTO permission_history (app_id, permission_type, old_status, new_status, timestamp, reason) VALUES (?, ?, ?, ?, ?, ?)",
                (app_id, permission_type.value, old_status.value, new_status.value, 
                 datetime.now().isoformat(), reason)
            )
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to log permission change: {e}")
    
    def _save_app_to_db(self, app: AppInfo) -> None:
        """Save app information to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert or update app
            cursor.execute(
                "INSERT OR REPLACE INTO apps VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (app.app_id, app.app_name, app.bundle_id, app.version, app.developer,
                 app.install_date, app.last_updated, app.app_store_app, app.signed,
                 app.risk_score, app.category)
            )
            
            # Delete existing permissions
            cursor.execute("DELETE FROM permissions WHERE app_id = ?", (app.app_id,))
            
            # Insert permissions
            for permission in app.permissions:
                cursor.execute(
                    "INSERT INTO permissions (app_id, permission_type, status, risk_level, description, last_used, usage_frequency, is_necessary, justification) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (app.app_id, permission.permission_type.value, permission.status.value,
                     permission.risk_level.value, permission.description, permission.last_used,
                     permission.usage_frequency, permission.is_necessary, permission.justification)
                )
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to save app to database: {e}")
    
    def _update_permission_in_db(self, app_id: str, permission: AppPermission) -> None:
        """Update permission in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "UPDATE permissions SET status = ?, last_used = ?, usage_frequency = ? WHERE app_id = ? AND permission_type = ?",
                (permission.status.value, permission.last_used, permission.usage_frequency,
                 app_id, permission.permission_type.value)
            )
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to update permission in database: {e}")
    
    def get_app_permissions(self, app_id: str) -> List[AppPermission]:
        """Get permissions for a specific app"""
        if app_id in self.apps:
            return self.apps[app_id].permissions
        return []
    
    def get_high_risk_apps(self, threshold: float = 70.0) -> List[AppInfo]:
        """Get apps with high risk scores"""
        return [app for app in self.apps.values() if app.risk_score >= threshold]
    
    def save_audit_report(self, report: PermissionAuditReport, filename: str) -> None:
        """Save audit report to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(asdict(report), f, indent=2, default=str)
            logger.info(f"Audit report saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save audit report: {e}")