"""
AI-CSPM Core Data Models
Defines semantic graph nodes, edge types, attack path models, and remediation schemas.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    WORKLOAD = "WORKLOAD"                     # Kubernetes Pod / Deployment
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"       # K8s ServiceAccount
    IAM_ROLE = "IAM_ROLE"                     # Cloud IAM Role (AWS/Azure/GCP)
    IAM_POLICY = "IAM_POLICY"                 # Cloud IAM Policy (HCL or JSON)
    KMS_KEY = "KMS_KEY"                       # Cloud KMS Customer Managed Key
    S3_BUCKET = "S3_BUCKET"                   # Cloud Storage Vault / Database
    UNKNOWN = "UNKNOWN"


class EdgeType(str, Enum):
    USES_SERVICE_ACCOUNT = "USES_SERVICE_ACCOUNT"
    IRSA_ASSUMES = "IRSA_ASSUMES"             # K8s SA assumes Cloud IAM Role via OIDC
    HAS_POLICY = "HAS_POLICY"                 # IAM Role attaches IAM Policy
    ALLOWS_DECRYPT = "ALLOWS_DECRYPT"         # IAM Policy grants Decrypt on KMS Key
    ENCRYPTS_BUCKET = "ENCRYPTS_BUCKET"       # KMS Key encrypts S3 Bucket


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PolicyStatement(BaseModel):
    sid: Optional[str] = None
    effect: str = "Allow"
    actions: List[str] = Field(default_factory=list)
    resources: List[str] = Field(default_factory=list)
    conditions: Dict[str, Any] = Field(default_factory=dict)


class BaseNode(BaseModel):
    id: str
    name: str
    type: NodeType
    layer: str  # "Kubernetes", "IAM", "Cryptography", "Storage"
    source_file: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class WorkloadNode(BaseNode):
    type: NodeType = NodeType.WORKLOAD
    layer: str = "Kubernetes"
    namespace: str = "default"
    service_account: str
    container_name: Optional[str] = None
    image: Optional[str] = None


class ServiceAccountNode(BaseNode):
    type: NodeType = NodeType.SERVICE_ACCOUNT
    layer: str = "Kubernetes"
    namespace: str = "default"
    role_arn: Optional[str] = None  # extracted from IRSA annotation


class IAMRoleNode(BaseNode):
    type: NodeType = NodeType.IAM_ROLE
    layer: str = "IAM"
    role_arn: str
    trust_policy: Dict[str, Any] = Field(default_factory=dict)
    oidc_provider: Optional[str] = None


class IAMPolicyNode(BaseNode):
    type: NodeType = NodeType.IAM_POLICY
    layer: str = "IAM"
    policy_arn: Optional[str] = None
    statements: List[PolicyStatement] = Field(default_factory=list)
    has_wildcard_decrypt: bool = False


class KMSKeyNode(BaseNode):
    type: NodeType = NodeType.KMS_KEY
    layer: str = "Cryptography"
    key_arn: str
    alias: Optional[str] = None
    rotation_enabled: bool = False


class S3BucketNode(BaseNode):
    type: NodeType = NodeType.S3_BUCKET
    layer: str = "Storage"
    bucket_name: str
    bucket_arn: str
    kms_key_arn: Optional[str] = None


class AttackPath(BaseModel):
    id: str
    title: str
    severity: Severity = Severity.CRITICAL
    nodes: List[Dict[str, Any]]
    steps: List[str]
    root_cause: str
    impact: str
    false_negative_tools: List[str] = Field(
        default_factory=lambda: ["Prowler v5.46", "ScoutSuite", "AWS Access Analyzer", "Checkov", "Trivy"]
    )


class RemediationResult(BaseModel):
    attack_path_id: str
    original_code: str
    remediated_code: str
    explanation: str
    least_privilege_changes: List[str]
    risk_reduction: str
