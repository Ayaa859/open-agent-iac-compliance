# Open-Agent Framework for Intelligent IaC Compliance Analysis

Hybrid OPA + LLM framework for Terraform compliance analysis using NIST SP 800-53 mappings.

## Features

- OPA-based deterministic policy enforcement
- LLM-powered violation enrichment
- Terraform remediation generation
- NIST SP 800-53 mapping
- Audit-ready Markdown reports
- Evaluation on IaC-Eval benchmark

## Architecture

The framework combines:
- Open Policy Agent (OPA)
- Rego policy rules
- Terraform static analysis
- LLM enrichment layer
- NIST compliance mapping

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python scripts/download_dataset.py
python scripts/prepare_dataset.py
python scripts/run_opa.py
python scripts/llm_enrichment.py
python scripts/generate_report.py
```

## Results

- Precision: 97.5%
- Recall: 88.5%
- F1 Score: 92.8%
- Accuracy: 91.5%

## Research Paper

See `/paper` for the full IEEE paper.
