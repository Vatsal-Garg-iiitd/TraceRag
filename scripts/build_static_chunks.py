"""
build_static_chunks.py

Bridges the static analysis pipeline (filtered_dataset.csv) into the
chunk + SQLite format expected by the downstream RAG pipeline:
  ssaf_filter → describer → qdrant_indexer → forensic_queries
  → prefetch_and_prune → llm_analyzer → verify_claims

Each APK row in filtered_dataset.csv is split by its pipe-separated
API calls. Every API call becomes one chunk (method-level) so that
ssaf_filter can classify it and the LLM can reason about it.
"""

import os
import sys
import json
import sqlite3
import pandas as pd
from loguru import logger

# Add project root to sys.path to allow config import
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import path_in_project

if len(sys.argv) < 2:
    print("Usage: python build_static_chunks.py <sample_id>")
    sys.exit(1)

SAMPLE_ID = int(sys.argv[1])
LOG_DIR = path_in_project(f"logs/sample_{SAMPLE_ID}")
DB_PATH = path_in_project("pipeline.db")
CHUNKS_PATH = LOG_DIR / "chunks.jsonl"

BASE_PATH = os.environ.get("MALWARE_PROJECT_BASE", str(path_in_project("data")))
FEATURES_PATH = os.environ.get("FEATURES_PATH", os.path.join(BASE_PATH, "features"))
# Reads the raw detailed dataset produced by extract_features_detailed.py
# (filter_features step is no longer in the pipeline — ssaf_filter handles it downstream)
FEATURES_CSV = os.path.join(FEATURES_PATH, "detailed_dataset.csv")


def split_pipe(value):
    """Split a pipe-separated string, ignoring None/empty."""
    if pd.isna(value) or str(value).strip() in ("", "None"):
        return []
    return [item.strip() for item in str(value).split("|") if item.strip()]


def build_jimple_stub(class_name, method_name, apk_name, label, permissions, strings):
    """Create a Jimple-like static representation of an API call."""
    perm_lines = "\n".join(f"    // uses-permission: {p}" for p in permissions[:8])
    string_lines = "\n".join(f"    // string evidence: \"{s}\"" for s in strings[:5])
    return (
        f"// === Static Analysis: {apk_name} [{label}] ===\n"
        f"// Permissions declared:\n{perm_lines}\n"
        f"// Suspicious strings observed:\n{string_lines}\n"
        f"public void {method_name}() {{\n"
        f"    // Detected API: {class_name}.{method_name}\n"
        f"    // Source: Static Smali decompilation (no dynamic trace)\n"
        f"}}"
    )


def build_chunks_from_static():
    os.makedirs(LOG_DIR, exist_ok=True)

    if not os.path.exists(FEATURES_CSV):
        logger.error(f"detailed_dataset.csv not found at {FEATURES_CSV}")
        logger.error("Run extract_features_detailed.py first and place APKs in data/apks/")
        sys.exit(1)

    df = pd.read_csv(FEATURES_CSV)
    logger.info(f"Loaded {len(df)} APK rows from filtered_dataset.csv")

    # ── SQLite setup ───────────────────────────────────────────────────────
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS jimple_methods (
        class_name TEXT, method_name TEXT, jimple_text TEXT,
        cfg_json TEXT, PRIMARY KEY (class_name, method_name))''')
    conn.execute('''CREATE TABLE IF NOT EXISTS callgraph (caller TEXT, callee TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS dynamic_edges (
        method TEXT, class TEXT, label TEXT,
        type TEXT DEFAULT "DYNAMIC_ONLY", ts INTEGER,
        UNIQUE(method, class, label))''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_derp ON dynamic_edges(method, class)')

    out = open(CHUNKS_PATH, "w")
    chunk_id = 0

    for _, row in df.iterrows():
        apk_name  = str(row.get("APK_Name", "unknown"))
        label     = str(row.get("Label", "Unknown"))
        perms     = split_pipe(row.get("Filtered_Permissions", ""))
        api_calls = split_pipe(row.get("Filtered_API_Calls", ""))
        strings   = split_pipe(row.get("Filtered_Strings", ""))

        if not api_calls:
            logger.warning(f"No filtered API calls for {apk_name}, skipping.")
            continue

        # Build a minimal call-graph: consecutive API calls in order
        for i in range(len(api_calls) - 1):
            if "." in api_calls[i] and "." in api_calls[i + 1]:
                conn.execute(
                    "INSERT OR IGNORE INTO callgraph VALUES (?,?)",
                    (api_calls[i], api_calls[i + 1])
                )

        for api_call in api_calls:
            if "." not in api_call:
                continue

            parts       = api_call.rsplit(".", 1)
            class_name  = parts[0]
            method_name = parts[1] if len(parts) > 1 else api_call

            jimple_text = build_jimple_stub(
                class_name, method_name, apk_name, label, perms, strings
            )

            conn.execute(
                "INSERT OR REPLACE INTO jimple_methods VALUES (?,?,?,?)",
                (class_name, method_name, jimple_text, "{}")
            )

            chunk = {
                "chunk_id":        chunk_id,
                "sample_id":       SAMPLE_ID,
                "class_name":      class_name,
                "method_name":     method_name,
                "thread_id":       0,
                "entry_ts_ns":     0,
                "exit_ts_ns":      0,
                "raw_jimple":      jimple_text,
                "kernel_syscalls": [],          # No Layer 1 — no strace
                "native_jni":      [],          # No Layer 1 — no JVMTI
                "callees":         [],
                "executed_cfg":    [],
                "ssaf_flagged":    False,
                # Extra static metadata (used by ssaf_filter regex patterns)
                "apk_name":        apk_name,
                "label":           label,
                "permissions":     perms,
                "suspicious_strings": strings,
            }
            out.write(json.dumps(chunk) + "\n")
            chunk_id += 1

    out.close()
    conn.commit()
    conn.close()
    logger.info(f"Built {chunk_id} static chunks → {CHUNKS_PATH}")
    logger.info(f"SQLite DB ready at {DB_PATH}")


if __name__ == "__main__":
    build_chunks_from_static()
