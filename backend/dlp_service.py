"""Data Loss Prevention (DLP) Engine Service

Monitors and enforces data protection policies across channels:
- USB/External drives
- Email & cloud uploads
- Network shares
- Printing & clipboard operations
"""

import hashlib
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel

# Data Types Classification
class DataClassification(str, Enum):
    PERSONAL = "personal_data"  # PII: names, SSN, etc.
    FINANCIAL = "financial"      # Card, bank accounts
    IP = "intellectual_property"  # Trade secrets, source code
    SENSITIVE = "sensitive"      # Medical, legal
    PUBLIC = "public"

# Channel Types
class Channel(str, Enum):
    USB = "usb"
    EXTERNAL_DRIVE = "external_drive"
    EMAIL = "email"
    CLOUD_UPLOAD = "cloud_upload"
    NETWORK_SHARE = "network_share"
    PRINT = "print"
    CLIPBOARD = "clipboard"

# Policy Actions
class PolicyAction(str, Enum):
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ALERT = "alert"
    LOG = "log"
    ENCRYPT = "encrypt"

class DLPPolicy(BaseModel):
    """DLP Policy Definition"""
    policy_id: str
    name: str
    description: str
    channels: List[Channel]
    data_types: List[DataClassification]
    action: PolicyAction
    severity: str  # low, medium, high, critical
    enabled: bool = True
    created_at: datetime

class DLPIncident(BaseModel):
    """DLP Violation Incident"""
    incident_id: str
    user_id: str
    device_id: str
    channel: Channel
    data_type: DataClassification
    file_name: str
    file_hash: str
    timestamp: datetime
    action_taken: PolicyAction
    severity: str
    description: str

class DLPService:
    """Main DLP Service Handler"""

    def __init__(self):
        self.policies: Dict[str, DLPPolicy] = {}
        self.incidents: List[DLPIncident] = []
        self.blocked_hashes: set = set()  # For fast lookup

    def create_policy(self, policy: DLPPolicy) -> Dict:
        """Create new DLP policy"""
        self.policies[policy.policy_id] = policy
        return {
            "status": "success",
            "policy_id": policy.policy_id,
            "message": f"Policy '{policy.name}' created successfully"
        }

    def classify_content(self, content: bytes, filename: str) -> DataClassification:
        """Classify content based on patterns and ML"""
        # Simple heuristic: check for common PII patterns
        content_str = content.decode('utf-8', errors='ignore').lower()
        
        if any(pattern in content_str for pattern in ['ssn-', 'social security', 'passport']):
            return DataClassification.PERSONAL
        elif any(pattern in content_str for pattern in ['card', 'account', 'bank']):
            return DataClassification.FINANCIAL
        elif any(pattern in content_str for pattern in ['proprietary', 'confidential', 'trade secret']):
            return DataClassification.IP
        else:
            return DataClassification.PUBLIC

    def check_policy(self, channel: Channel, data_type: DataClassification, 
                    file_name: str, file_content: bytes) -> Optional[DLPPolicy]:
        """Check if content violates any policy"""
        for policy in self.policies.values():
            if (policy.enabled and 
                channel in policy.channels and 
                data_type in policy.data_types):
                return policy
        return None

    def handle_violation(self, user_id: str, device_id: str, channel: Channel,
                        file_name: str, file_content: bytes) -> DLPIncident:
        """Process DLP violation"""
        data_type = self.classify_content(file_content, file_name)
        policy = self.check_policy(channel, data_type, file_name, file_content)
        
        file_hash = hashlib.sha256(file_content).hexdigest()
        
        incident = DLPIncident(
            incident_id=f"DLP-{datetime.now().timestamp()}",
            user_id=user_id,
            device_id=device_id,
            channel=channel,
            data_type=data_type,
            file_name=file_name,
            file_hash=file_hash,
            timestamp=datetime.now(),
            action_taken=policy.action if policy else PolicyAction.LOG,
            severity=policy.severity if policy else "medium",
            description=f"Attempted {channel.value} access to {data_type.value} via {file_name}"
        )
        
        self.incidents.append(incident)
        
        if policy and policy.action == PolicyAction.BLOCK:
            self.blocked_hashes.add(file_hash)
        
        return incident

    def get_incidents(self, limit: int = 100) -> List[DLPIncident]:
        """Retrieve recent incidents"""
        return sorted(self.incidents, key=lambda x: x.timestamp, reverse=True)[:limit]

    def export_audit_log(self) -> str:
        """Export DLP audit log for compliance (DPDP/GDPR)"""
        log_lines = ["timestamp,user_id,device_id,channel,data_type,action,severity\n"]
        for incident in self.incidents:
            log_lines.append(
                f"{incident.timestamp},{incident.user_id},{incident.device_id},"
                f"{incident.channel.value},{incident.data_type.value},"
                f"{incident.action_taken.value},{incident.severity}\n"
            )
        return "".join(log_lines)

# Global instance
dlp_service = DLPService()
