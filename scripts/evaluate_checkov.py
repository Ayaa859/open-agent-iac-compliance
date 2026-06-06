import json
import os

# Load OPA results
with open("opa_results.json", encoding="utf-8") as f:
    opa_results = json.load(f)

# Only evaluate files that were not skipped
evaluated = [r for r in opa_results if not r.get("skipped")]

# Load Checkov results (UTF-16 output on Windows)
with open("checkov_results.json", encoding="utf-16") as f:
    checkov = json.load(f)

# Collect files that have at least one failed check
failed_files = set()

for check in checkov["results"]["failed_checks"]:
    path = check.get("file_path", "").replace("\\", "/")
    filename = os.path.basename(path)
    failed_files.add(filename)

# Compute confusion matrix
tp = fp = tn = fn = 0

for r in evaluated:
    filename = r["file"]
    actual = r["expected_label"]

    predicted = (
        "NON_COMPLIANT"
        if filename in failed_files
        else "COMPLIANT"
    )

    if actual == "NON_COMPLIANT" and predicted == "NON_COMPLIANT":
        tp += 1
    elif actual == "NON_COMPLIANT" and predicted == "COMPLIANT":
        fn += 1
    elif actual == "COMPLIANT" and predicted == "NON_COMPLIANT":
        fp += 1
    elif actual == "COMPLIANT" and predicted == "COMPLIANT":
        tn += 1

# Metrics
precision = tp / (tp + fp) if (tp + fp) else 0
recall = tp / (tp + fn) if (tp + fn) else 0
f1 = (
    2 * precision * recall / (precision + recall)
    if (precision + recall)
    else 0
)
accuracy = (tp + tn) / (tp + tn + fp + fn)

print("\nCHECKOV BASELINE RESULTS")
print("-" * 50)
print(f"Evaluated files : {len(evaluated)}")
print(f"TP : {tp}")
print(f"FN : {fn}")
print(f"FP : {fp}")
print(f"TN : {tn}")

print("\nMetrics")
print("-" * 50)
print(f"Precision : {precision * 100:.1f}%")
print(f"Recall    : {recall * 100:.1f}%")
print(f"F1 Score  : {f1 * 100:.1f}%")
print(f"Accuracy  : {accuracy * 100:.1f}%")