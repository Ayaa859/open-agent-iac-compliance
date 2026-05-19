from datasets import load_dataset
import json
import os

# load the dataset
print("Downloading IaC-Eval dataset...")
ds = load_dataset("autoiac-project/iac-eval")

# See what splits exist
print("Available splits:", ds)

# Get the correct split name
split_name = list(ds.keys())[0]
print(f"\nUsing split: '{split_name}'")
print(f"Number of entries: {len(ds[split_name])}")

# Print first entry to see structure
print("\nFirst entry:")
print(ds[split_name][0])

# Save all entries to a folder
os.makedirs("iac_dataset", exist_ok=True)

for i, entry in enumerate(ds[split_name]):
    filename = f"iac_dataset/scenario_{i:03d}.json"
    with open(filename, 'w') as f:
        json.dump(entry, f, indent=2)

print(f"\nSaved {len(ds[split_name])} scenarios to /iac_dataset folder")