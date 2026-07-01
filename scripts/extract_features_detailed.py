import os
import re
import shutil
import subprocess
import pandas as pd

BASE_PATH = r"D:\LLM_Malware_project"

BENIGN_PATH = os.path.join(BASE_PATH, "benign")
MALWARE_PATH = os.path.join(BASE_PATH, "malware")
DECODED_PATH = os.path.join(BASE_PATH, "decoded")
FEATURES_PATH = os.path.join(BASE_PATH, "features")

APKTOOL_PATH = r"D:\apktool\apktool.bat"

os.makedirs(DECODED_PATH, exist_ok=True)
os.makedirs(FEATURES_PATH, exist_ok=True)


def decode_apk(apk_path):
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    output_folder = os.path.join(DECODED_PATH, apk_name)

    if os.path.exists(output_folder):
        print("Already decoded. Skipping decoding.")
        return output_folder

    command = [
        APKTOOL_PATH,
        "d",
        apk_path,
        "-o",
        output_folder,
        "-f"
    ]

    subprocess.run(command, check=True)
    return output_folder


def extract_permissions(decoded_folder):
    manifest_path = os.path.join(decoded_folder, "AndroidManifest.xml")

    if not os.path.exists(manifest_path):
        return []

    with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
        manifest = f.read()

    permissions = re.findall(r"android\.permission\.[A-Z_]+", manifest)
    permissions = sorted(list(set(permissions)))

    return permissions


def extract_api_calls(decoded_folder, max_items=100):
    api_calls = set()

    for root, dirs, files in os.walk(decoded_folder):
        for file in files:
            if file.endswith(".smali"):
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    calls = re.findall(r"invoke-\w+.*?->.*?\(", content)
                    api_calls.update(calls)

                except Exception as e:
                    print("Skipping file:", file_path)
                    print("Reason:", e)

    api_calls = sorted(list(api_calls))
    return api_calls[:max_items], len(api_calls)


def extract_strings(decoded_folder, max_items=100):
    strings = set()

    suspicious_keywords = [
        "http", "https", "sms", "imei", "device", "token",
        "password", "login", "admin", "root", "su",
        "cmd", "shell", "apk", "dex", "payload",
        "bank", "upi", "otp", "contact", "location"
    ]

    for root, dirs, files in os.walk(decoded_folder):
        for file in files:
            if file.endswith(".smali"):
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    found_strings = re.findall(r'const-string.*?,\s*"([^"]*)"', content)

                    for s in found_strings:
                        s_clean = s.strip()

                        if len(s_clean) < 4:
                            continue

                        lower_s = s_clean.lower()

                        if any(keyword in lower_s for keyword in suspicious_keywords):
                            strings.add(s_clean)

                except Exception as e:
                    print("Skipping file:", file_path)
                    print("Reason:", e)

    strings = sorted(list(strings))
    return strings[:max_items], len(strings)


def list_to_text(items):
    if not items:
        return "None"
    return " | ".join(items)


def process_apk(apk_path, label):
    print("\nProcessing:", os.path.basename(apk_path))

    decoded_folder = decode_apk(apk_path)
    print("Decoding Done")

    permissions_list = extract_permissions(decoded_folder)
    print("Permissions Done:", len(permissions_list))

    api_calls_list, api_calls_count = extract_api_calls(decoded_folder)
    print("API Calls Done:", api_calls_count)

    strings_list, strings_count = extract_strings(decoded_folder)
    print("Important Strings Done:", strings_count)

    return {
        "APK_Name": os.path.basename(apk_path),
        "Permissions_Count": len(permissions_list),
        "Permissions_List": list_to_text(permissions_list),
        "API_Calls_Count": api_calls_count,
        "API_Calls_List": list_to_text(api_calls_list),
        "Important_Strings_Count": strings_count,
        "Important_Strings_List": list_to_text(strings_list),
        "Label": label
    }


def collect_apk_jobs():
    apk_jobs = []

    for file in os.listdir(BENIGN_PATH):
        if file.lower().endswith(".apk"):
            apk_jobs.append((os.path.join(BENIGN_PATH, file), "Benign"))

    for file in os.listdir(MALWARE_PATH):
        if file.lower().endswith(".apk"):
            apk_jobs.append((os.path.join(MALWARE_PATH, file), "Malware"))

    return apk_jobs


all_results = []
failed_apks = []

output_csv = os.path.join(FEATURES_PATH, "detailed_dataset.csv")
failed_csv = os.path.join(FEATURES_PATH, "failed_detailed_apks.csv")

apk_jobs = collect_apk_jobs()
total_apks = len(apk_jobs)

print("Total APKs found:", total_apks)

for index, (apk_path, label) in enumerate(apk_jobs, start=1):
    apk_name = os.path.basename(apk_path)

    print("\n" + "=" * 60)
    print(f"Processing APK {index}/{total_apks}: {apk_name}")
    print(f"Label: {label}")
    print("=" * 60)

    try:
        result = process_apk(apk_path, label)
        all_results.append(result)

        pd.DataFrame(all_results).to_csv(output_csv, index=False)
        print("Progress Saved:", output_csv)

    except Exception as e:
        print("Failed APK:", apk_name)
        print("Error:", e)

        failed_apks.append({
            "APK_Name": apk_name,
            "Label": label,
            "Error": str(e)
        })

        pd.DataFrame(failed_apks).to_csv(failed_csv, index=False)
        continue


pd.DataFrame(all_results).to_csv(output_csv, index=False)

print("\nDetailed Dataset Saved Successfully!")
print("Saved at:", output_csv)

if failed_apks:
    pd.DataFrame(failed_apks).to_csv(failed_csv, index=False)
    print("Some APKs failed.")
else:
    print("No APK failed.")