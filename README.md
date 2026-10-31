# 🛡️ AI-CSPM: Contextual Multi-Tier Cloud Security Platform

**Academic Graduation Project • Empirical Research Lab Benchmark & Tool Implementation**

---

## 🌟 How to Run the Platform

### 1. ⚛️ React Web Dashboard (Recommended for Presentation)
Double-click:
👉 `F:\CSPM_Project\run_react_dashboard.bat`

Or run via terminal:
```bash
cd F:\CSPM_Project\ai-cspm-dashboard
npm run dev -- --open
```
*Opens interactive cybersecurity dashboard on `http://localhost:5173` with visual DAG graph, hop-by-hop attack paths, and AI Terraform diff.*

---

### 2. 💻 Python Terminal CLI Scanner
Double-click:
👉 `F:\CSPM_Project\run_ai_cspm.bat`

Or run via terminal:
```bash
python F:\CSPM_Project\run_ai_cspm.py
```
*Executes multi-tier ingestion, traverses the graph, and outputs rich color-coded trees and tables.*

---

## 📁 Project Directory Structure

```
F:\CSPM_Project/
├── ai-cspm-dashboard/             # ⚛️ Modern React + Vite Dashboard (Dark Cybersecurity Theme)
│   ├── src/
│   │   ├── components/AttackGraph.jsx # Interactive Multi-Tier DAG Visualizer
│   │   ├── App.jsx               # Main Dashboard with Tabs, Metrics & AI Diff
│   │   └── data/scanResults.json # Empirically validated benchmark scan data
├── AI_CSPM_Engine/                # 🐍 Python Core Ingestion & Graph Analyzer Engine
│   ├── core/                      # Graph, Models, and Attack Path Analyzer
│   ├── ingestion/                 # Kubernetes & Terraform Parsers
│   └── ai/                        # AI Scoped Remediation Engine
├── Benchmark_Lab/                 # 🔬 Live AWS Infrastructure & Raw Evidence Files
├── run_react_dashboard.bat        # 🚀 1-Click Launcher for React Web Dashboard
└── run_ai_cspm.bat                # 🚀 1-Click Launcher for Python CLI Scanner
```
