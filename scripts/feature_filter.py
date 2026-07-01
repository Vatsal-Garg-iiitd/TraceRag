import os
import re
import pandas as pd

import sys

# Add project root to sys.path to allow config import
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import path_in_project

BASE_PATH = os.environ.get("MALWARE_PROJECT_BASE", str(path_in_project("data")))
FEATURES_PATH = os.environ.get("FEATURES_PATH", os.path.join(BASE_PATH, "features"))

INPUT_CSV = os.path.join(FEATURES_PATH, "detailed_dataset.csv")
OUTPUT_CSV = os.path.join(FEATURES_PATH, "filtered_dataset.csv")


SECURITY_PERMISSIONS = [
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "READ_PHONE_STATE", "CALL_PHONE",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "RECORD_AUDIO", "CAMERA",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "RECEIVE_BOOT_COMPLETED",
    "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES",
    "QUERY_ALL_PACKAGES"
]


SECURITY_API_KEYWORDS = [
    "Runtime", "exec", "ProcessBuilder",
    "DexClassLoader", "PathClassLoader",
    "SmsManager", "TelephonyManager",
    "getDeviceId", "getSubscriberId", "getLine1Number",
    "ContentResolver", "query",
    "getInstalledPackages", "getInstalledApplications",
    "PackageManager",
    "HttpURLConnection", "URLConnection", "Socket",
    "Cipher", "SecretKey", "MessageDigest", "Base64",
    "loadLibrary", "System.load",
    "Class.forName", "Method.invoke"
]


def split_features(value):
    if pd.isna(value) or str(value).strip() == "" or str(value).strip() == "None":
        return []
    return [item.strip() for item in str(value).split("|") if item.strip()]


def list_to_text(items):
    if not items:
        return "None"
    return " | ".join(items)


def filter_permissions(permission_text):
    permissions = split_features(permission_text)
    filtered = []

    for permission in permissions:
        for keyword in SECURITY_PERMISSIONS:
            if keyword in permission:
                filtered.append(permission)

    return sorted(set(filtered))


def clean_api_name(api):
    match = re.search(r"L([^;]+);->([^\(]+)\(", api)

    if not match:
        return None

    class_name = match.group(1).replace("/", ".")
    method_name = match.group(2)

    short_class = class_name.split(".")[-1]

    return f"{short_class}.{method_name}"


def filter_api_calls(api_text):
    api_calls = split_features(api_text)
    filtered = []

    for api in api_calls:
        if not any(keyword.lower() in api.lower() for keyword in SECURITY_API_KEYWORDS):
            continue

        clean_name = clean_api_name(api)

        if clean_name:
            filtered.append(clean_name)

    return sorted(set(filtered))


def filter_strings(strings_text):
    strings = split_features(strings_text)
    filtered = []

    noisy_words = [
        "issue explanation", "write below", "supported",
        "index", "supertype", "result", "passwordfield",
        "debug", "test", "example", "sample", "todo",
        "null", "true", "false",
        "layout", "drawable", "resource"
    ]

    strong_keywords = [
        "http", "https",
        ".php", ".jsp", ".asp",
        ".exe", ".dex", ".apk", ".jar",
        "token", "apikey", "api_key",
        "password", "passwd", "login",
        "otp", "sms",
        "imei", "imsi", "deviceid",
        "bank", "upi", "wallet",
        "payload", "shell", "cmd",
        "root", "su",
        "/system/bin/sh",
        "/system/xbin/su",
        "contact", "location",
        "camera", "microphone"
    ]

    for s in strings:
        s = str(s).strip()
        lower = s.lower()

        if len(s) < 4 or len(s) > 150:
            continue

        if s.startswith("$") or s.startswith("@"):
            continue

        if lower.startswith("android.") or lower.startswith("java."):
            continue

        if any(word in lower for word in noisy_words):
            continue

        if lower.startswith("http://") or lower.startswith("https://"):
            filtered.append(s)
            continue

        if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", s):
            filtered.append(s)
            continue

        if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", s):
            filtered.append(s)
            continue

        if any(keyword in lower for keyword in strong_keywords):
            filtered.append(s)

    return sorted(set(filtered))


df = pd.read_csv(INPUT_CSV)

filtered_rows = []

for _, row in df.iterrows():
    permissions = filter_permissions(row.get("Permissions_List", ""))
    api_calls = filter_api_calls(row.get("API_Calls_List", ""))
    strings = filter_strings(row.get("Important_Strings_List", ""))

    filtered_rows.append({
        "APK_Name": row["APK_Name"],
        "Filtered_Permissions_Count": len(permissions),
        "Filtered_Permissions": list_to_text(permissions),
        "Filtered_API_Calls_Count": len(api_calls),
        "Filtered_API_Calls": list_to_text(api_calls),
        "Filtered_Strings_Count": len(strings),
        "Filtered_Strings": list_to_text(strings),
        "Label": row["Label"]
    })

filtered_df = pd.DataFrame(filtered_rows)
filtered_df.to_csv(OUTPUT_CSV, index=False)

print("Filtered dataset created successfully!")
print("Saved at:", OUTPUT_CSV)
print("Total rows:", len(filtered_df))