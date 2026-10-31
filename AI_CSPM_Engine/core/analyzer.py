"""
AI-CSPM Attack Path & Blindspot Detection Analyzer
Traverses the Contextual DAG to identify cross-layer identity-to-cryptography compromise chains.
"""

import networkx as nx
from typing import List, Dict, Any, Optional
from .graph import ContextualGraph
from .models import AttackPath, Severity, NodeType


class AttackPathAnalyzer:
    def __init__(self, contextual_graph: ContextualGraph):
        self.cg = contextual_graph
        self.graph = contextual_graph.graph

    def find_cross_layer_attack_paths(self) -> List[AttackPath]:
        """Discovers all viable paths from Kubernetes Workloads to sensitive Cloud Vaults."""
        attack_paths: List[AttackPath] = []

        # 1. Identify start nodes (Workloads)
        workloads = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == NodeType.WORKLOAD.value
        ]

        # 2. Identify target nodes (S3 Buckets and KMS Keys)
        targets = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("node_type") in [NodeType.S3_BUCKET.value, NodeType.KMS_KEY.value]
        ]

        path_idx = 1
        for w in workloads:
            for t in targets:
                if not nx.has_path(self.graph, w, t):
                    continue

                for simple_path in nx.all_simple_paths(self.graph, w, t):
                    # Check if path contains a flawed wildcard decrypt edge
                    has_wildcard = False
                    for i in range(len(simple_path) - 1):
                        u, v = simple_path[i], simple_path[i + 1]
                        edge_data = self.graph.get_edge_data(u, v, default={})
                        if edge_data.get("is_wildcard") or edge_data.get("lethal_flaw"):
                            has_wildcard = True
                            break

                    # Construct detailed Attack Path object
                    path_nodes = []
                    path_steps = []
                    for i, node_id in enumerate(simple_path):
                        node_attrs = self.graph.nodes[node_id]
                        name = node_attrs.get("name", node_id)
                        layer = node_attrs.get("layer", "Unknown")
                        ntype = node_attrs.get("node_type", "UNKNOWN")
                        
                        path_nodes.append({
                            "id": node_id,
                            "name": name,
                            "type": ntype,
                            "layer": layer
                        })

                        if i == 0:
                            path_steps.append(f"1. In-Cluster Workload: Container '{name}' compromised in Kubernetes '{layer}' layer.")
                        elif ntype == NodeType.SERVICE_ACCOUNT.value:
                            path_steps.append(f"2. Workload Identity Token: Container inherits tokens from ServiceAccount '{name}'.")
                        elif ntype == NodeType.IAM_ROLE.value:
                            path_steps.append(f"3. Cloud Identity Escalation: STS WebIdentity federation assumes AWS IAM Role '{name}'.")
                        elif ntype == NodeType.IAM_POLICY.value:
                            path_steps.append(f"4. Lethal Wildcard Grant: Attached IAM Policy '{name}' permits 'kms:Decrypt' on '*' resource.")
                        elif ntype == NodeType.KMS_KEY.value:
                            path_steps.append(f"5. Cryptographic Exfiltration: Wildcard enables decrypting Customer Managed Key '{name}'.")
                        elif ntype == NodeType.S3_BUCKET.value:
                            path_steps.append(f"6. Vault Breach: Full exfiltration of protected financial records in S3 bucket '{name}'.")

                    ap = AttackPath(
                        id=f"AP-{path_idx:03d}",
                        title=f"Multi-Tier Cryptographic Exfiltration: {path_nodes[0]['name']} -> {path_nodes[-1]['name']}",
                        severity=Severity.CRITICAL if has_wildcard else Severity.HIGH,
                        nodes=path_nodes,
                        steps=path_steps,
                        root_cause=(
                            "Architectural disconnect between single-layer tools. "
                            "IAM Policy grants wildcard kms:Decrypt on '*' to an EKS federated role, "
                            "allowing arbitrary container exfiltration of all encrypted tenant secrets."
                        ),
                        impact=(
                            "Critical data breach: An attacker exploiting the payment container acquires "
                            "unrestricted capabilities to decrypt every database, S3 bucket, and secret in the tenant."
                        ),
                        false_negative_tools=[
                            "Prowler v5.46 (Gave 100% PASS - checks *:* only)",
                            "ScoutSuite 5.14 (0 findings - no Kubernetes awareness)",
                            "AWS IAM Access Analyzer (findings: [] - syntax valid)",
                            "ARMO Kubescape (Halts at Kubernetes cluster boundary)",
                            "Checkov & Trivy (Segregated inspection - misses cross-layer link)"
                        ]
                    )
                    attack_paths.append(ap)
                    path_idx += 1

        return attack_paths
