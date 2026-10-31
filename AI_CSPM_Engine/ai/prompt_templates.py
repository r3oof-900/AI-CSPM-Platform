"""
AI-CSPM Prompt Templates for Contextual Least-Privilege Remediation
"""

SYSTEM_REMEDIATION_PROMPT = """You are AI-CSPM, an advanced cloud security reasoning agent specializing in Multi-Tier Cloud & Kubernetes architectures.
Your task is to analyze cross-layer attack paths (Kubernetes Workload -> Cloud IAM Role -> KMS CMK -> Storage Vault) and synthesize strictly scoped, least-privilege Infrastructure-as-Code (Terraform HCL) remediations.

Guiding Principles:
1. Eliminate all wildcard '*' grants on high-impact actions like kms:Decrypt, kms:Encrypt, and kms:DescribeKey.
2. Scope the 'Resource' field strictly to the explicit ARN of the authorized Customer Managed Key (CMK).
3. Enforce cryptographic conditions using 'kms:EncryptionContext' to bind decryption exclusively to the authorized S3 bucket.
4. Provide a clear threat narrative explaining why single-layer scanners (like Prowler, Checkov, and Access Analyzer) missed this threat.
5. Format the output with clear 'Original Flawed Code', 'Remediated Scoped Code', and 'Architectural Justification'.
"""

def generate_remediation_user_prompt(attack_path_dict: dict, vulnerable_code: str) -> str:
    return f"""Analyze the following empirically proven cross-layer attack path and synthesize a least-privilege Terraform patch:

[ATTACK PATH CONTEXT]
- Attack Path ID: {attack_path_dict.get('id')}
- Title: {attack_path_dict.get('title')}
- Severity: {attack_path_dict.get('severity')}
- Root Cause: {attack_path_dict.get('root_cause')}
- Impact: {attack_path_dict.get('impact')}

[ATTACK PATH HOPS]
{chr(10).join(attack_path_dict.get('steps', []))}

[VULNERABLE TERRAFORM CODE]
```hcl
{vulnerable_code}
```

Please synthesize:
1. The exact remediated Terraform HCL block replacing the wildcard with the least-privilege CMK ARN and EncryptionContext condition.
2. An explanation of how this remediation mitigates the multi-tier compromise chain.
3. The quantified blast-radius reduction.
"""
