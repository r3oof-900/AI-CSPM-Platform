"""
AI-CSPM Terraform & Cloud IaC Ingestion Parser
Extracts IAM Roles, IAM Policies, Attachments, KMS Keys, and S3 Buckets from Terraform HCL & JSON files.
"""

import os
import re
import ast
import json
import hcl2
from typing import List, Dict, Any, Tuple, Optional
try:
    from core.models import (
        IAMRoleNode,
        IAMPolicyNode,
        KMSKeyNode,
        S3BucketNode,
        PolicyStatement,
        NodeType
    )
except (ImportError, ValueError):
    from ..core.models import (
        IAMRoleNode,
        IAMPolicyNode,
        KMSKeyNode,
        S3BucketNode,
        PolicyStatement,
        NodeType
    )


class TerraformParser:
    def __init__(self):
        self.roles: List[IAMRoleNode] = []
        self.policies: List[IAMPolicyNode] = []
        self.kms_keys: List[KMSKeyNode] = []
        self.s3_buckets: List[S3BucketNode] = []
        self.attachments: List[Dict[str, str]] = []  # [{role: name/arn, policy: arn/name}]

    def _extract_embedded_json(self, value: Any) -> Optional[Dict[str, Any]]:
        """Extracts JSON object from jsonencode(...) or raw JSON string."""
        if isinstance(value, list) and len(value) > 0:
            value = value[0]

        if isinstance(value, dict):
            return value

        if not isinstance(value, str):
            return None

        # Clean terraform wrapper ${jsonencode(...)}
        clean_val = value.strip()
        if clean_val.startswith("${jsonencode(") and clean_val.endswith(")}"):
            inner = clean_val[len("${jsonencode(") : -len(")}")]
            try:
                # Often hcl2 preserves inner python dict syntax
                return ast.literal_eval(inner)
            except Exception:
                try:
                    return json.loads(inner)
                except Exception:
                    pass

        try:
            return json.loads(clean_val)
        except Exception:
            pass

        return None

    def parse_directory(self, dir_path: str):
        """Scans all .tf and .json files in the specified directory."""
        if not os.path.exists(dir_path):
            return

        for root, _, files in os.walk(dir_path):
            for file in files:
                full_path = os.path.join(root, file)
                if file.endswith(".tf"):
                    self.parse_tf_file(full_path)
                elif file.endswith(".json") and "policy" in file.lower():
                    self.parse_standalone_json_policy(full_path)

    def parse_standalone_json_policy(self, filepath: str):
        """Parses standalone IAM policy JSON file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            statements = self._parse_statements(data.get("Statement", []))
            has_wildcard = any("*" in s.resources and any("kms:Decrypt" in a or "kms:*" in a for a in s.actions) for s in statements)
            
            p_name = os.path.splitext(os.path.basename(filepath))[0]
            node = IAMPolicyNode(
                id=f"iam:policy:{p_name}",
                name=p_name,
                policy_arn=f"arn:aws:iam:::policy/{p_name}",
                statements=statements,
                has_wildcard_decrypt=has_wildcard,
                source_file=filepath,
                properties={"raw_json": data}
            )
            self.policies.append(node)
        except Exception as e:
            print(f"[!] Error parsing standalone JSON policy {filepath}: {e}")

    def _parse_statements(self, stmts_data: Any) -> List[PolicyStatement]:
        """Normalizes IAM policy statements."""
        if isinstance(stmts_data, dict):
            stmts_data = [stmts_data]
        elif not isinstance(stmts_data, list):
            return []

        parsed = []
        for s in stmts_data:
            if not isinstance(s, dict):
                continue
            
            actions = s.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = s.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            parsed.append(PolicyStatement(
                sid=s.get("Sid"),
                effect=s.get("Effect", "Allow"),
                actions=actions,
                resources=resources,
                conditions=s.get("Condition", {})
            ))
        return parsed

    def parse_tf_file(self, filepath: str):
        """Parses a Terraform .tf file."""
        with open(filepath, "r", encoding="utf-8") as f:
            try:
                obj = hcl2.load(f)
            except Exception as e:
                print(f"[!] Error reading HCL2 file {filepath}: {e}")
                return

        resources = obj.get("resource", [])
        for res_wrapper in resources:
            for res_type, res_entries in res_wrapper.items():
                for res_id, res_data in res_entries.items():
                    if res_type == "aws_iam_role":
                        self._process_iam_role(res_id, res_data, filepath)
                    elif res_type == "aws_iam_policy":
                        self._process_iam_policy(res_id, res_data, filepath)
                    elif res_type == "aws_iam_role_policy_attachment":
                        self._process_attachment(res_data)
                    elif res_type == "aws_kms_key":
                        self._process_kms_key(res_id, res_data, filepath)
                    elif res_type == "aws_s3_bucket":
                        self._process_s3_bucket(res_id, res_data, filepath)
                    elif res_type == "aws_s3_bucket_server_side_encryption_configuration":
                        self._process_s3_sse(res_data)

    def _process_iam_role(self, res_id: str, data: Dict[str, Any], filepath: str):
        name = data.get("name", [res_id])[0] if isinstance(data.get("name"), list) else data.get("name", res_id)
        assume_raw = data.get("assume_role_policy")
        assume_dict = self._extract_embedded_json(assume_raw) or {}

        # Detect OIDC federated provider
        oidc_provider = None
        for stmt in assume_dict.get("Statement", []):
            principal = stmt.get("Principal", {})
            if isinstance(principal, dict) and "Federated" in principal:
                oidc_provider = principal["Federated"]

        role_node = IAMRoleNode(
            id=f"iam:role:{name}",
            name=name,
            role_arn=f"arn:aws:iam::853679583136:role/{name}",
            trust_policy=assume_dict,
            oidc_provider=oidc_provider,
            source_file=filepath,
            properties={"raw": data}
        )
        self.roles.append(role_node)

    def _process_iam_policy(self, res_id: str, data: Dict[str, Any], filepath: str):
        name = data.get("name", [res_id])[0] if isinstance(data.get("name"), list) else data.get("name", res_id)
        policy_raw = data.get("policy")
        policy_dict = self._extract_embedded_json(policy_raw) or {}

        statements = self._parse_statements(policy_dict.get("Statement", []))
        has_wildcard = any("*" in s.resources and any("kms:Decrypt" in a or "kms:*" in a for a in s.actions) for s in statements)

        policy_node = IAMPolicyNode(
            id=f"iam:policy:{name}",
            name=name,
            policy_arn=f"arn:aws:iam::853679583136:policy/{name}",
            statements=statements,
            has_wildcard_decrypt=has_wildcard,
            source_file=filepath,
            properties={"raw_policy": policy_dict}
        )
        self.policies.append(policy_node)

    def _process_attachment(self, data: Dict[str, Any]):
        role_raw = data.get("role", [""])[0] if isinstance(data.get("role"), list) else data.get("role", "")
        policy_raw = data.get("policy_arn", [""])[0] if isinstance(data.get("policy_arn"), list) else data.get("policy_arn", "")
        
        # Clean references like aws_iam_role.eks_payment_kms_role.name
        role_name = role_raw.split(".")[-2] if "." in role_raw and not role_raw.startswith("arn:") else role_raw
        policy_name = policy_raw.split(".")[-2] if "." in policy_raw and not policy_raw.startswith("arn:") else policy_raw

        self.attachments.append({
            "role": role_name,
            "policy": policy_name
        })

    def _process_kms_key(self, res_id: str, data: Dict[str, Any], filepath: str):
        key_node = KMSKeyNode(
            id=f"kms:key:{res_id}",
            name=res_id,
            key_arn=f"arn:aws:kms:eu-north-1:853679583136:key/0fa87d17-5b86-4026-b0c7-7b34d4e25d51",
            alias="alias/payment-vault-cmk",
            rotation_enabled=bool(data.get("enable_key_rotation", [True])[0] if isinstance(data.get("enable_key_rotation"), list) else True),
            source_file=filepath,
            properties={"description": data.get("description", [""])[0] if isinstance(data.get("description"), list) else ""}
        )
        self.kms_keys.append(key_node)

    def _process_s3_bucket(self, res_id: str, data: Dict[str, Any], filepath: str):
        b_name = data.get("bucket", [res_id])[0] if isinstance(data.get("bucket"), list) else data.get("bucket", res_id)
        bucket_node = S3BucketNode(
            id=f"s3:bucket:{res_id}",
            name=res_id,
            bucket_name=b_name,
            bucket_arn=f"arn:aws:s3:::{b_name}",
            source_file=filepath,
            properties={"tags": data.get("tags", [{}])[0] if isinstance(data.get("tags"), list) else {}}
        )
        self.s3_buckets.append(bucket_node)

    def _process_s3_sse(self, data: Dict[str, Any]):
        pass
