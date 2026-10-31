"""
AI-CSPM Engine Quick Launcher
Runs the AI-CSPM scan directly from the project root.
"""

import os
import sys

# Change directory to AI_CSPM_Engine and execute CLI
engine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "AI_CSPM_Engine")
sys.path.insert(0, engine_dir)

from run_cli import run_scan

if __name__ == "__main__":
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Benchmark_Lab", "01_IaC_and_Manifests")
    run_scan(target)
