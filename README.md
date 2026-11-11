# Open-Agent Framework for Intelligent IaC Compliance Analysis

Hybrid **Open Policy Agent (OPA) + LLM** pipeline that checks Terraform configurations against NIST SP 800-53
(control families AC, SC and AU) and produces draft, audit-oriented compliance reports.
This repository accompanies the paper *An Open-Agent Framework for Intelligent Compliance Analysis in
Infrastructure as Code Using Large Language Models* (Discover Computing, under revision).

> **Scope.** All results hold for the evaluated setting only: 16 Rego rules, three NIST SP 800-53 control
> families (AC, SC, AU), eight AWS resource types, Terraform configurations from the IaC-Eval benchmark, and one
> language model (Llama 3.3 70B). Other frameworks, IaC formats, cloud providers and models are design intent and
> were not evaluated.

## How it works

1. **Ingest** Terraform (HCL2 parsed with python-hcl2) and normalise it for OPA.
2. **Detect** violations with deterministic Rego rules (`policies/`), routed by resource type.
3. **Enrich** each violation type once with an LLM (Llama 3.3 70B via Cloudflare Workers AI): a plain-language
   explanation and a generic remediation snippet. NIST control names and descriptions come from a fixed lookup
   table, not from the model.
4. **Report** in Markdown (`reports/audit_report.md`). The explanations and remediations are **drafts for human
   review**; the model never sees the original resource.

## Headline results (human-validated labels)

The substring heuristic that first labelled the IaC-Eval scenarios agreed with human labels on only **58.3%** of a
random sample (all errors were missed violations), so every result below is computed on human labels
(90 files labelled by two annotators; 9 of the 90 are compliant).

| System (random sample of 60 files) | Precision | Recall | F1 |
|---|---|---|---|
| Rule layer (this work) | 96.3% | 47.3% | 63.4% |
| Checkov 3.3.6, scope-matched (variant B2) | 100% | 83.6% | 91.1% |
| Rule layer, all 90 validated files | 97.8% | 55.6% | 70.9% |

* LLM-only baseline (same model, no OPA, 90 files): recall 100% but 89 of 90 files flagged, and the model chose the
  framework's NIST control for only 68% of true findings.
* Generated remediations: 16 of 16 are valid HCL; applied inside real violating files, **8 of 16** pass
  `terraform validate`, the policy engine and Checkov; a human rater judged 4 of 16 usable as written.

The rule library fires only on explicit misconfiguration and has known gaps (no RDS missing-field rule, no
companion security-group rules). **No finding is weak evidence of compliance.** See the paper, Sections 6 and 7.

## Repository layout

```
policies/                    4 Rego files (16 rules)
terraform/                   the 231 Terraform configurations (compliant/ and non_compliant/ = heuristic labels)
datasets/ground_truth.csv    21 injected configurations with exact labels
dataset_annotations.csv      heuristic (preliminary) labels of the IaC-Eval scenarios
scripts/                     pipeline, evaluation and verification scripts (see below)
scripts/annotation/          sampling, annotation sheets and agreement analysis
human_labels_90.csv          agreed human labels (90 files); human_labels_90_with_rules.csv adds the failed checks
opa_results.json             OPA output for the 231 files
enriched_results.json        LLM enrichment (the version assessed in the paper; re-running gives different text)
checkov_results.json         Checkov 3.3.6 output; checkov_scope_mapping.csv is the check mapping (paper, Appendix C)
llm_only_runs.jsonl          raw LLM-only outputs (540 calls); llm_only_results.csv is the summary
fix_verification.csv         per-fix verification (terraform validate, OPA, Checkov); fix_verification_files/
rescan_results.csv           isolated OPA re-scan of the 16 remediation snippets
reports/                     generated audit report and the excerpt shown to the rater
annotation/                  annotation rubric, anonymised annotator sheets, blank rating sheet
```

## Requirements

* Python 3.13
* **Open Policy Agent 1.16.1** on the PATH
* **Terraform v1.17.0** on the PATH (only for `apply_and_verify_fixes.py`; AWS provider v6.72.0 is downloaded by Terraform)
* A Cloudflare Workers AI account (only for the LLM steps)

Two Python environments are needed, because Checkov bundles its own HCL parser, which conflicts with python-hcl2:

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt

python -m venv ck_env
.\ck_env\Scripts\python.exe -m pip install -r requirements-checkov.txt
```

**Credentials.** The LLM scripts read `CF_ACCOUNT_ID` and `CF_API_TOKEN` from environment variables. Never put a
token in a file. The Workers AI free tier has a daily allowance; the 540-call LLM-only baseline needs a paid plan or
several days.

```powershell
$env:CF_ACCOUNT_ID = "your-account-id"
$env:CF_API_TOKEN  = "your-token"
```

## Reproducing the paper (run from the repository root, main environment)

| Paper item | Command |
|---|---|
| Dataset and heuristic labels | `python scripts\download_dataset.py` then `python scripts\prepare_dataset.py` |
| Table 6 (resource types) | `python scripts\count_resource_types.py` |
| OPA detection, Tables 12 to 14 | `python scripts\run_opa.py` |
| LLM enrichment (needs credentials) | `python scripts\llm_enrichment.py` |
| Audit report | `python scripts\generate_report.py` |
| Checkov variants, Tables 18 and 19, Appendix D | `python scripts\scope_matched_checkov.py --labels human_labels_90.csv --only-labelled` |
| LLM-only baseline (needs credentials) | `python scripts\llm_only_baseline.py --labels human_labels_90.csv --subset random60 --runs 3` |
| LLM-only analysis, Tables 21 and 22 | `python scripts\analyze_llm_only.py --labels human_labels_90_with_rules.csv --subset all` |
| Isolated re-scan of the remediations | `python scripts\rescan_remediations.py` |
| Remediation verification, Tables 15 to 17, Appendix E | `python scripts\apply_and_verify_fixes.py --per-rule 1 --checkov-python ".\ck_env\Scripts\python.exe"` |

`scope_matched_checkov.py` reads `checkov_results.json`, produced by Checkov 3.3.6 (JSON output) in the `ck_env`
environment. `llm_only_baseline.py` resumes if interrupted.

## Validation of the ground truth

`scripts/annotation/` contains the code that drew the blinded random sample (seed 42) and the stratified sample,
built the annotation sheets and computed agreement. The rubric is in `annotation/` (paper, Appendix A). The two
annotators agreed on all 90 files. The rubric and draft annotation notes were prepared with the assistance of a large
language model; the labels were assigned by the annotators.

## Limitations

Small validated sample (90 files, 9 compliant), one benchmark, one model, AWS and Terraform only, rule library gaps,
and a single, non-auditor rater for remediation quality. The generated remediations are generic examples and must be
reviewed before use.

## Citation

Al-Jabali, A., Al-Dala'ien, M.: An Open-Agent Framework for Intelligent Compliance Analysis in Infrastructure as
Code Using Large Language Models. Discover Computing (under revision). Code and data: release [tag], archived at
[DOI].

## License

See `LICENSE`. The IaC-Eval benchmark is distributed under its own terms (see its original source).
