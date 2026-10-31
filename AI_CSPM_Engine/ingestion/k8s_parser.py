"""
AI-CSPM Kubernetes Ingestion Parser
Extracts Workloads, ServiceAccounts, and Cloud Workload Identity bindings (e.g. AWS IRSA).
"""

import os
import yaml
from typing import List, Tuple, Dict, Any
try:
    from core.models import WorkloadNode, ServiceAccountNode, NodeType
except (ImportError, ValueError):
    from ..core.models import WorkloadNode, ServiceAccountNode, NodeType


class K8sParser:
    def __init__(self):
        self.workloads: List[WorkloadNode] = []
        self.service_accounts: List[ServiceAccountNode] = []

    def parse_file(self, filepath: str) -> Tuple[List[WorkloadNode], List[ServiceAccountNode]]:
        """Parses a Kubernetes multi-document YAML file."""
        if not os.path.exists(filepath):
            return [], []

        with open(filepath, "r", encoding="utf-8") as f:
            try:
                documents = list(yaml.safe_load_all(f))
            except Exception as e:
                print(f"[!] Error parsing K8s YAML {filepath}: {e}")
                return [], []

        file_workloads = []
        file_sas = []

        for doc in documents:
            if not doc or not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", "unnamed")
            namespace = metadata.get("namespace", "default")

            if kind == "ServiceAccount":
                annotations = metadata.get("annotations", {}) or {}
                # AWS EKS IRSA annotation
                role_arn = (
                    annotations.get("eks.amazonaws.com/role-arn")
                    or annotations.get("azure.workload.identity/client-id")
                )
                
                sa_node = ServiceAccountNode(
                    id=f"k8s:sa:{namespace}:{name}",
                    name=name,
                    namespace=namespace,
                    role_arn=role_arn,
                    source_file=filepath,
                    properties={
                        "annotations": annotations,
                        "labels": metadata.get("labels", {})
                    }
                )
                file_sas.append(sa_node)

            elif kind in ["Deployment", "Pod", "StatefulSet", "DaemonSet"]:
                spec = doc.get("spec", {})
                template_spec = spec.get("template", {}).get("spec", {}) if kind != "Pod" else spec
                
                sa_name = template_spec.get("serviceAccountName") or template_spec.get("serviceAccount") or "default"
                containers = template_spec.get("containers", [])
                primary_container = containers[0] if containers else {}

                workload_node = WorkloadNode(
                    id=f"k8s:workload:{namespace}:{name}",
                    name=name,
                    namespace=namespace,
                    service_account=sa_name,
                    container_name=primary_container.get("name"),
                    image=primary_container.get("image"),
                    source_file=filepath,
                    properties={
                        "kind": kind,
                        "replicas": spec.get("replicas", 1),
                        "securityContext": primary_container.get("securityContext", {}),
                        "env": primary_container.get("env", [])
                    }
                )
                file_workloads.append(workload_node)

        self.workloads.extend(file_workloads)
        self.service_accounts.extend(file_sas)
        return file_workloads, file_sas
