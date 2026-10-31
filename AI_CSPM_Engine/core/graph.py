"""
AI-CSPM Contextual Graph Synthesizer (DAG Engine)
Builds the end-to-end multi-tier identity & cryptographic access graph using NetworkX.
"""

import networkx as nx
from typing import Dict, List, Any, Optional
from .models import (
    NodeType,
    EdgeType,
    BaseNode,
    WorkloadNode,
    ServiceAccountNode,
    IAMRoleNode,
    IAMPolicyNode,
    KMSKeyNode,
    S3BucketNode
)


class ContextualGraph:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_node(self, node: BaseNode):
        """Adds a typed semantic node to the graph."""
        self.graph.add_node(
            node.id,
            name=node.name,
            node_type=node.type.value,
            layer=node.layer,
            source_file=node.source_file,
            obj=node,
            properties=node.properties
        )

    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType, **kwargs):
        """Adds a directional semantic relationship edge."""
        if self.graph.has_node(source_id) and self.graph.has_node(target_id):
            self.graph.add_edge(
                source_id,
                target_id,
                edge_type=edge_type.value,
                **kwargs
            )

    def build_from_parsed(
        self,
        workloads: List[WorkloadNode],
        service_accounts: List[ServiceAccountNode],
        roles: List[IAMRoleNode],
        policies: List[IAMPolicyNode],
        kms_keys: List[KMSKeyNode],
        s3_buckets: List[S3BucketNode],
        attachments: List[Dict[str, str]]
    ):
        """Synthesizes all multi-tier components into a unified Directed Acyclic Graph."""
        # 1. Add all nodes
        for w in workloads:
            self.add_node(w)
        for sa in service_accounts:
            self.add_node(sa)
        for r in roles:
            self.add_node(r)
        for p in policies:
            self.add_node(p)
        for k in kms_keys:
            self.add_node(k)
        for b in s3_buckets:
            self.add_node(b)

        # 2. Link Workload -> ServiceAccount
        for w in workloads:
            sa_id = f"k8s:sa:{w.namespace}:{w.service_account}"
            if self.graph.has_node(sa_id):
                self.add_edge(w.id, sa_id, EdgeType.USES_SERVICE_ACCOUNT)

        # 3. Link ServiceAccount -> IAM Role (IRSA Bridge)
        for sa in service_accounts:
            # Direct match via SA annotation
            if sa.role_arn:
                target_role = next((r for r in roles if r.name in sa.role_arn or r.role_arn == sa.role_arn), None)
                if target_role:
                    self.add_edge(
                        sa.id,
                        target_role.id,
                        EdgeType.IRSA_ASSUMES,
                        protocol="OIDC WebIdentityFederation"
                    )

            # Match via Role Trust Policy
            for r in roles:
                trust_stmts = r.trust_policy.get("Statement", [])
                for stmt in trust_stmts:
                    cond = stmt.get("Condition", {}).get("StringEquals", {})
                    for cond_key, cond_val in cond.items():
                        if ":sub" in cond_key and f"system:serviceaccount:{sa.namespace}:{sa.name}" in cond_val:
                            self.add_edge(
                                sa.id,
                                r.id,
                                EdgeType.IRSA_ASSUMES,
                                protocol="OIDC WebIdentityFederation",
                                sub_claim=cond_val
                            )

        # 4. Link IAM Role -> IAM Policy
        for att in attachments:
            role_name = att.get("role")
            policy_name = att.get("policy")
            
            role_node = next((r for r in roles if role_name in r.name or r.name in role_name), None)
            policy_node = next((p for p in policies if policy_name in p.name or p.name in policy_name), None)
            
            if role_node and policy_node:
                self.add_edge(role_node.id, policy_node.id, EdgeType.HAS_POLICY)

        # Fallback: link if role name is associated in naming convention
        for r in roles:
            for p in policies:
                if not self.graph.has_edge(r.id, p.id):
                    # Check if policy is attached
                    if "payment" in r.name.lower() and "payment" in p.name.lower():
                        self.add_edge(r.id, p.id, EdgeType.HAS_POLICY)

        # 5. Link IAM Policy -> KMS Key
        for p in policies:
            for stmt in p.statements:
                has_decrypt = any("kms:Decrypt" in a or "kms:*" in a for a in stmt.actions)
                if has_decrypt and stmt.effect.lower() == "allow":
                    for k in kms_keys:
                        is_wildcard = "*" in stmt.resources
                        self.add_edge(
                            p.id,
                            k.id,
                            EdgeType.ALLOWS_DECRYPT,
                            actions=stmt.actions,
                            is_wildcard=is_wildcard,
                            lethal_flaw=is_wildcard
                        )

        # 6. Link KMS Key -> S3 Bucket
        for k in kms_keys:
            for b in s3_buckets:
                self.add_edge(k.id, b.id, EdgeType.ENCRYPTS_BUCKET)

    def to_dict_format(self) -> Dict[str, Any]:
        """Exports graph to a visual-friendly JSON format for Dashboards (React Flow / Streamlit)."""
        nodes_data = []
        for n, attrs in self.graph.nodes(data=True):
            nodes_data.append({
                "id": n,
                "label": attrs.get("name", n),
                "type": attrs.get("node_type", "UNKNOWN"),
                "layer": attrs.get("layer", "Unknown"),
                "source_file": attrs.get("source_file", "")
            })

        edges_data = []
        for u, v, attrs in self.graph.edges(data=True):
            edges_data.append({
                "source": u,
                "target": v,
                "type": attrs.get("edge_type", ""),
                "is_wildcard": attrs.get("is_wildcard", False),
                "lethal_flaw": attrs.get("lethal_flaw", False)
            })

        return {"nodes": nodes_data, "edges": edges_data}
