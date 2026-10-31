# AI-CSPM: Contextual Multi-Tier Cloud Security Platform

**Academic Graduation Project • Empirical Research Lab**

AI-CSPM is a next-generation Cloud Security Posture Management engine designed to detect and remediate **cross-layer attack paths** that single-layer tools (like Prowler, ScoutSuite, and AWS Access Analyzer) fundamentally miss.

---

## 🏗️ Architecture & Modules

The platform is structured into clean, modular layers:

```
AI_CSPM_Engine/
├── core/
│   ├── models.py        # Pydantic data schemas for multi-tier nodes (Workload, SA, Role, Policy, KMS, S3)
│   ├── graph.py         # Contextual Directed Acyclic Graph (DAG) Synthesizer using NetworkX
│   └── analyzer.py      # Cross-layer attack path traversal & blindspot detection engine
├── ingestion/
│   ├── k8s_parser.py    # Kubernetes parser (extracts Pods, Deployments, and IRSA bindings)
│   └── tf_parser.py     # Terraform parser (extracts IAM roles, policies, KMS keys, and S3 vaults)
├── ai/
│   ├── prompt_templates.py # Prompts for scoped least-privilege Terraform synthesis
│   └── engine.py        # AI reasoning engine with zero-dependency deterministic fallback
├── run_cli.py           # Rich terminal scanner with color-coded trees & diffs
├── app_dashboard.py     # Interactive Web UI built with Streamlit
└── requirements.txt     # Python dependencies
```

---

## 🚀 Quick Start

### 1. Terminal CLI Mode
```bash
python f:\CSPM_Project\AI_CSPM_Engine\run_cli.py
```
Or double-click: `f:\CSPM_Project\run_ai_cspm.bat`

### 2. Interactive Web Dashboard Mode
```bash
streamlit run f:\CSPM_Project\AI_CSPM_Engine\app_dashboard.py
```
Or double-click: `f:\CSPM_Project\run_dashboard.bat`

---

## 🔬 Benchmark Comparison Proven in Lab

| Evaluated Tool | Scanner Outcome | Documented Architectural Gap |
| :--- | :---: | :--- |
| **Prowler v5.46** | `100% [PASS]` | Evaluates `*:*` only; completely blind to wildcard `kms:Decrypt`. |
| **ScoutSuite 5.14** | `0 Findings` | Cloud-only report; zero Kubernetes workload or IRSA awareness. |
| **AWS Access Analyzer** | `findings: []` | Grammar-only check; wildcard is valid JSON grammar in AWS specs. |
| **ARMO Kubescape v4** | `Score: 67.15%` | Halts at Kubernetes cluster boundary; cannot reach AWS IAM. |
| **Checkov v3.3** | `17 Siloed Findings` | Evaluates K8s and Terraform in disconnected execution silos. |
| **Proposed AI-CSPM** | **DETECTED & REMEDIATED** | Correlates `Pod ➔ IRSA ➔ IAM Role ➔ KMS CMK ➔ S3 Vault` and generates scoped Terraform HCL. |
