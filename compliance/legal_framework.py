#!/usr/bin/env python3
"""
Legal & Procedural Compliance Framework
=====================================

This module implements a comprehensive legal authority validation system
with Rules of Engagement (ROE) integration to ensure only authorized operations.

Author: Compliance Team
Created: 2025-01-04
Version: 1.0.0
"""

import json
import hashlib
import hmac
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('compliance/audit_logs/legal_framework.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AuthorityLevel(Enum):
    """Authority levels for operations"""
    ADMINISTRATIVE = "administrative"
    JUDICIAL = "judicial"
    EMERGENCY = "emergency"
    NATIONAL_SECURITY = "national_security"
    LAW_ENFORCEMENT = "law_enforcement"

class OperationType(Enum):
    """Types of operations requiring authorization"""
    SURVEILLANCE = "surveillance"
    DATA_COLLECTION = "data_collection"
    NETWORK_MONITORING = "network_monitoring"
    ENDPOINT_ACCESS = "endpoint_access"
    THREAT_HUNTING = "threat_hunting"
    INCIDENT_RESPONSE = "incident_response"

class ComplianceStatus(Enum):
    """Compliance check results"""
    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"
    EXPIRED = "expired"
    SUSPENDED = "suspended"

@dataclass
class LegalAuthorization:
    """Legal authorization document structure"""
    authorization_id: str
    authority_level: AuthorityLevel
    operation_type: OperationType
    issuing_authority: str
    target_scope: Dict[str, Any]
    valid_from: datetime
    valid_until: datetime
    conditions: List[str]
    dual_control_required: bool
    human_rights_assessment: bool
    export_control_cleared: bool
    digital_signature: str
    created_at: datetime
    created_by: str
    
    def is_valid(self) -> bool:
        """Check if authorization is currently valid"""
        now = datetime.utcnow()
        return self.valid_from <= now <= self.valid_until

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        # Convert datetime objects to ISO format
        data['valid_from'] = self.valid_from.isoformat()
        data['valid_until'] = self.valid_until.isoformat()
        data['created_at'] = self.created_at.isoformat()
        data['authority_level'] = self.authority_level.value
        data['operation_type'] = self.operation_type.value
        return data

@dataclass
class RulesOfEngagement:
    """Rules of Engagement configuration"""
    roe_id: str
    name: str
    scope: Dict[str, Any]
    authorized_operations: List[OperationType]
    prohibited_operations: List[OperationType]
    geographic_restrictions: List[str]
    temporal_restrictions: Dict[str, Any]
    data_handling_rules: Dict[str, Any]
    escalation_procedures: Dict[str, Any]
    approval_matrix: Dict[str, List[str]]
    created_at: datetime
    version: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['authorized_operations'] = [op.value for op in self.authorized_operations]
        data['prohibited_operations'] = [op.value for op in self.prohibited_operations]
        return data

class LegalAuthorityValidator:
    """Main class for legal authority validation and ROE enforcement"""
    
    def __init__(self, config_path: str = "compliance/config/legal_config.json"):
        """Initialize the legal authority validator"""
        self.config_path = config_path
        self.config = self._load_config()
        self.encryption_key = self._generate_encryption_key()
        self.authorizations: Dict[str, LegalAuthorization] = {}
        self.roe_configurations: Dict[str, RulesOfEngagement] = {}
        self.audit_trail: List[Dict[str, Any]] = []
        
        # Ensure required directories exist
        os.makedirs("compliance/audit_logs", exist_ok=True)
        os.makedirs("compliance/authorizations", exist_ok=True)
        os.makedirs("compliance/config", exist_ok=True)
        
        logger.info("Legal Authority Validator initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            "retention_period_years": 7,
            "dual_control_threshold": ["SURVEILLANCE", "DATA_COLLECTION"],
            "mandatory_human_rights_assessment": ["SURVEILLANCE", "ENDPOINT_ACCESS"],
            "export_control_required": ["NETWORK_MONITORING", "THREAT_HUNTING"],
            "max_authorization_duration_days": 365,
            "emergency_authorization_duration_hours": 72
        }
        
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return {**default_config, **json.load(f)}
        except Exception as e:
            logger.warning(f"Could not load config: {e}. Using defaults.")
        
        return default_config
    
    def _generate_encryption_key(self) -> Fernet:
        """Generate encryption key for sensitive data"""
        password = os.environ.get('LEGAL_FRAMEWORK_KEY', 'default-key-change-in-production')
        password_bytes = password.encode()
        salt = b'legal_framework_salt'  # In production, use random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return Fernet(key)
    
    def create_authorization(
        self,
        authority_level: AuthorityLevel,
        operation_type: OperationType,
        issuing_authority: str,
        target_scope: Dict[str, Any],
        duration_days: int,
        conditions: List[str],
        created_by: str
    ) -> str:
        """Create a new legal authorization"""
        
        # Validate duration
        max_duration = self.config.get("max_authorization_duration_days", 365)
        if duration_days > max_duration:
            raise ValueError(f"Authorization duration cannot exceed {max_duration} days")
        
        # Generate authorization ID
        auth_id = str(uuid.uuid4())
        
        # Check requirements based on operation type
        dual_control_required = operation_type.value.upper() in self.config.get("dual_control_threshold", [])
        human_rights_assessment = operation_type.value.upper() in self.config.get("mandatory_human_rights_assessment", [])
        export_control_cleared = operation_type.value.upper() in self.config.get("export_control_required", [])
        
        # Create authorization
        now = datetime.utcnow()
        authorization = LegalAuthorization(
            authorization_id=auth_id,
            authority_level=authority_level,
            operation_type=operation_type,
            issuing_authority=issuing_authority,
            target_scope=target_scope,
            valid_from=now,
            valid_until=now + timedelta(days=duration_days),
            conditions=conditions,
            dual_control_required=dual_control_required,
            human_rights_assessment=human_rights_assessment,
            export_control_cleared=export_control_cleared,
            digital_signature=self._generate_digital_signature(auth_id, issuing_authority),
            created_at=now,
            created_by=created_by
        )
        
        # Store authorization
        self.authorizations[auth_id] = authorization
        self._save_authorization(authorization)
        
        # Log audit event
        self._log_audit_event("AUTHORIZATION_CREATED", {
            "authorization_id": auth_id,
            "authority_level": authority_level.value,
            "operation_type": operation_type.value,
            "issuing_authority": issuing_authority
        })
        
        logger.info(f"Legal authorization created: {auth_id}")
        return auth_id
    
    def validate_operation(self, authorization_id: str, operation_details: Dict[str, Any]) -> Tuple[ComplianceStatus, str]:
        """Validate an operation against legal authorization"""
        
        # Check if authorization exists
        if authorization_id not in self.authorizations:
            self._log_audit_event("VALIDATION_FAILED", {
                "authorization_id": authorization_id,
                "reason": "Authorization not found"
            })
            return ComplianceStatus.DENIED, "Authorization not found"
        
        authorization = self.authorizations[authorization_id]
        
        # Check if authorization is valid
        if not authorization.is_valid():
            self._log_audit_event("VALIDATION_FAILED", {
                "authorization_id": authorization_id,
                "reason": "Authorization expired"
            })
            return ComplianceStatus.EXPIRED, "Authorization expired"
        
        # Check scope compliance
        if not self._check_scope_compliance(authorization.target_scope, operation_details):
            self._log_audit_event("VALIDATION_FAILED", {
                "authorization_id": authorization_id,
                "reason": "Operation outside authorized scope"
            })
            return ComplianceStatus.DENIED, "Operation outside authorized scope"
        
        # Check dual control requirement
        if authorization.dual_control_required:
            if not operation_details.get("dual_control_approved", False):
                self._log_audit_event("VALIDATION_PENDING", {
                    "authorization_id": authorization_id,
                    "reason": "Dual control approval required"
                })
                return ComplianceStatus.PENDING, "Dual control approval required"
        
        # Check human rights assessment
        if authorization.human_rights_assessment:
            if not operation_details.get("human_rights_cleared", False):
                self._log_audit_event("VALIDATION_PENDING", {
                    "authorization_id": authorization_id,
                    "reason": "Human rights assessment required"
                })
                return ComplianceStatus.PENDING, "Human rights assessment required"
        
        # Check export control
        if authorization.export_control_cleared:
            if not operation_details.get("export_control_cleared", False):
                self._log_audit_event("VALIDATION_PENDING", {
                    "authorization_id": authorization_id,
                    "reason": "Export control clearance required"
                })
                return ComplianceStatus.PENDING, "Export control clearance required"
        
        # Validation successful
        self._log_audit_event("VALIDATION_APPROVED", {
            "authorization_id": authorization_id,
            "operation_type": authorization.operation_type.value
        })
        
        return ComplianceStatus.APPROVED, "Operation authorized"
    
    def create_roe_configuration(
        self,
        name: str,
        scope: Dict[str, Any],
        authorized_operations: List[OperationType],
        prohibited_operations: List[OperationType],
        geographic_restrictions: List[str],
        created_by: str
    ) -> str:
        """Create Rules of Engagement configuration"""
        
        roe_id = str(uuid.uuid4())
        
        roe = RulesOfEngagement(
            roe_id=roe_id,
            name=name,
            scope=scope,
            authorized_operations=authorized_operations,
            prohibited_operations=prohibited_operations,
            geographic_restrictions=geographic_restrictions,
            temporal_restrictions={},
            data_handling_rules={},
            escalation_procedures={},
            approval_matrix={},
            created_at=datetime.utcnow(),
            version="1.0"
        )
        
        self.roe_configurations[roe_id] = roe
        self._save_roe_configuration(roe)
        
        self._log_audit_event("ROE_CREATED", {
            "roe_id": roe_id,
            "name": name,
            "created_by": created_by
        })
        
        logger.info(f"Rules of Engagement created: {roe_id}")
        return roe_id
    
    def _check_scope_compliance(self, authorized_scope: Dict[str, Any], operation_details: Dict[str, Any]) -> bool:
        """Check if operation is within authorized scope"""
        
        # Check geographic scope
        if "geographic_area" in authorized_scope:
            operation_location = operation_details.get("location")
            if operation_location and operation_location not in authorized_scope["geographic_area"]:
                return False
        
        # Check target type scope
        if "target_types" in authorized_scope:
            operation_target_type = operation_details.get("target_type")
            if operation_target_type and operation_target_type not in authorized_scope["target_types"]:
                return False
        
        # Check data type scope
        if "data_types" in authorized_scope:
            operation_data_types = operation_details.get("data_types", [])
            authorized_data_types = authorized_scope["data_types"]
            if not all(dt in authorized_data_types for dt in operation_data_types):
                return False
        
        return True
    
    def _generate_digital_signature(self, auth_id: str, issuing_authority: str) -> str:
        """Generate digital signature for authorization"""
        message = f"{auth_id}:{issuing_authority}:{datetime.utcnow().isoformat()}"
        signature = hmac.new(
            key=b'digital_signature_key',  # In production, use proper key management
            msg=message.encode(),
            digestmod=hashlib.sha256
        ).hexdigest()
        return signature
    
    def _save_authorization(self, authorization: LegalAuthorization):
        """Save authorization to encrypted file"""
        filename = f"compliance/authorizations/{authorization.authorization_id}.json"
        encrypted_data = self.encryption_key.encrypt(
            json.dumps(authorization.to_dict()).encode()
        )
        with open(filename, 'wb') as f:
            f.write(encrypted_data)
    
    def _save_roe_configuration(self, roe: RulesOfEngagement):
        """Save ROE configuration to file"""
        filename = f"compliance/config/roe_{roe.roe_id}.json"
        with open(filename, 'w') as f:
            json.dump(roe.to_dict(), f, indent=2)
    
    def _log_audit_event(self, event_type: str, details: Dict[str, Any]):
        """Log audit event with tamper-evident properties"""
        timestamp = datetime.utcnow().isoformat()
        event = {
            "timestamp": timestamp,
            "event_type": event_type,
            "details": details,
            "hash": self._calculate_event_hash(timestamp, event_type, details)
        }
        
        self.audit_trail.append(event)
        
        # Write to audit log file
        audit_log_file = f"compliance/audit_logs/legal_audit_{datetime.utcnow().strftime('%Y%m%d')}.json"
        with open(audit_log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
    
    def _calculate_event_hash(self, timestamp: str, event_type: str, details: Dict[str, Any]) -> str:
        """Calculate hash for audit event integrity"""
        event_string = f"{timestamp}:{event_type}:{json.dumps(details, sort_keys=True)}"
        return hashlib.sha256(event_string.encode()).hexdigest()
    
    def get_authorization_status(self, authorization_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of authorization"""
        if authorization_id not in self.authorizations:
            return None
        
        authorization = self.authorizations[authorization_id]
        return {
            "authorization_id": authorization_id,
            "status": "valid" if authorization.is_valid() else "expired",
            "authority_level": authorization.authority_level.value,
            "operation_type": authorization.operation_type.value,
            "valid_until": authorization.valid_until.isoformat(),
            "dual_control_required": authorization.dual_control_required,
            "human_rights_assessment": authorization.human_rights_assessment,
            "export_control_cleared": authorization.export_control_cleared
        }
    
    def revoke_authorization(self, authorization_id: str, reason: str, revoked_by: str):
        """Revoke an existing authorization"""
        if authorization_id in self.authorizations:
            # Mark as expired
            self.authorizations[authorization_id].valid_until = datetime.utcnow()
            
            self._log_audit_event("AUTHORIZATION_REVOKED", {
                "authorization_id": authorization_id,
                "reason": reason,
                "revoked_by": revoked_by
            })
            
            logger.info(f"Authorization revoked: {authorization_id}")
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        now = datetime.utcnow()
        
        # Count authorizations by status
        valid_auths = sum(1 for auth in self.authorizations.values() if auth.is_valid())
        expired_auths = len(self.authorizations) - valid_auths
        
        # Count by operation type
        op_type_counts = {}
        for auth in self.authorizations.values():
            op_type = auth.operation_type.value
            op_type_counts[op_type] = op_type_counts.get(op_type, 0) + 1
        
        # Recent audit events
        recent_events = [
            event for event in self.audit_trail 
            if datetime.fromisoformat(event["timestamp"]) > (now - timedelta(days=30))
        ]
        
        report = {
            "generated_at": now.isoformat(),
            "summary": {
                "total_authorizations": len(self.authorizations),
                "valid_authorizations": valid_auths,
                "expired_authorizations": expired_auths,
                "roe_configurations": len(self.roe_configurations)
            },
            "operation_type_breakdown": op_type_counts,
            "recent_audit_events": len(recent_events),
            "compliance_status": "COMPLIANT" if valid_auths > 0 else "NO_ACTIVE_AUTHORIZATIONS"
        }
        
        return report

def main():
    """Example usage of the Legal Authority Validator"""
    
    # Initialize validator
    validator = LegalAuthorityValidator()
    
    # Create a sample authorization
    auth_id = validator.create_authorization(
        authority_level=AuthorityLevel.LAW_ENFORCEMENT,
        operation_type=OperationType.SURVEILLANCE,
        issuing_authority="District Court #1",
        target_scope={
            "geographic_area": ["domestic"],
            "target_types": ["individual"],
            "data_types": ["communications", "location"]
        },
        duration_days=90,
        conditions=[
            "Limited to specific target individual",
            "No bulk data collection",
            "Weekly progress reports required"
        ],
        created_by="Judge Smith"
    )
    
    print(f"Created authorization: {auth_id}")
    
    # Validate an operation
    operation_details = {
        "location": "domestic",
        "target_type": "individual",
        "data_types": ["communications"],
        "dual_control_approved": True,
        "human_rights_cleared": True
    }
    
    status, message = validator.validate_operation(auth_id, operation_details)
    print(f"Validation result: {status.value} - {message}")
    
    # Generate compliance report
    report = validator.generate_compliance_report()
    print(f"Compliance report: {json.dumps(report, indent=2)}")

if __name__ == "__main__":
    main()
