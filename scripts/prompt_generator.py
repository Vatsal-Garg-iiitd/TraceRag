import os
import pandas as pd

import sys

# Add project root to sys.path to allow config import
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import path_in_project

BASE_PATH = os.environ.get("MALWARE_PROJECT_BASE", str(path_in_project("data")))
FEATURES_PATH = os.environ.get("FEATURES_PATH", os.path.join(BASE_PATH, "features"))

INPUT_CSV = os.path.join(FEATURES_PATH, "filtered_dataset.csv")
OUTPUT_CSV = os.path.join(FEATURES_PATH, "prompts.csv")


def clean_text(value):
    if pd.isna(value) or str(value).strip() == "" or str(value).strip() == "None":
        return "None"
    return str(value).replace(" | ", "\n")


def create_prompt(row):
    permissions = clean_text(row.get("Filtered_Permissions", "None"))
    api_calls = clean_text(row.get("Filtered_API_Calls", "None"))
    strings = clean_text(row.get("Filtered_Strings", "None"))
    label = row["Label"]

    prompt = f"""<s>[INST]
You are an Android malware analyst.

Analyze the following Android application using its static features.

Permissions:
{permissions}

API Calls:
{api_calls}

Important Strings:
{strings}

Question:
Classify this Android application as either Benign or Malware.
[/INST]
{label}</s>"""

    return prompt


df = pd.read_csv(INPUT_CSV)

prompt_rows = []

for _, row in df.iterrows():
    prompt_rows.append({
        "Prompt": create_prompt(row),
        "Label": row["Label"]
    })

prompt_df = pd.DataFrame(prompt_rows)
prompt_df.to_csv(OUTPUT_CSV, index=False)

print("Prompts created successfully!")
print("Saved at:", OUTPUT_CSV)
print("Total prompts:", len(prompt_df))