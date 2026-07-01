import sqlite3
import json
from loguru import logger

from config import path_in_project

import sys

if len(sys.argv) < 2:
    print("Usage: python derp_recovery.py <sample_id>")
    sys.exit(1)

SAMPLE_ID = int(sys.argv[1])
LOG_DIR = path_in_project(f"logs/sample_{SAMPLE_ID}")

DB_PATH = path_in_project("pipeline.db")
CHUNKS_PATH = LOG_DIR / "chunks.jsonl"
REPORT_PATH = LOG_DIR / "derp_report.json"

def run_derp():
    try:
        logger.info("Initializing DERP Engine and connecting to SQLite DB...")
        conn = sqlite3.connect(DB_PATH)
        
        # Ensure dynamic_edges table exists
        conn.execute('''CREATE TABLE IF NOT EXISTS dynamic_edges (
            method TEXT, class TEXT, label TEXT,
            type TEXT DEFAULT 'DYNAMIC_ONLY',
            ts INTEGER,
            UNIQUE(method, class, label))''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_derp ON dynamic_edges(method, class)')
        
        if not os.path.exists(CHUNKS_PATH):
            logger.error("chunks.jsonl not found!")
            return
            
        recovered_edges = []
        
        # Read chunks
        with open(CHUNKS_PATH, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                chunk = json.loads(line)
                method = chunk.get('method_name', '')
                class_name = chunk.get('class_name', '')
                executed_cfg = chunk.get('executed_cfg', [])
                entry_ts = chunk.get('entry_ts_ns', 0)
                
                # Fetch static labels
                row = conn.execute(
                    'SELECT cfg_json FROM jimple_methods WHERE class_name=? AND method_name=?',
                    (class_name, method)
                ).fetchone()
                
                static_labels = set()
                if row and row[0]:
                    try:
                        cfg_json = json.loads(row[0])
                        static_labels = set(cfg_json.keys())
                    except Exception as e:
                        logger.warning(f"Error parsing cfg_json for {class_name}.{method}: {e}")
                
                # Compare
                dynamic_only = set(executed_cfg) - static_labels
                
                for label in dynamic_only:
                    logger.info(f"DERP recovered dynamic edge: '{label}' in method {class_name}.{method}")
                    
                    # Insert into SQLite
                    conn.execute(
                        'INSERT OR IGNORE INTO dynamic_edges (method, class, label, type, ts) VALUES (?,?,?,?,?)',
                        (method, class_name, label, 'DYNAMIC_ONLY', entry_ts)
                    )
                    
                    recovered_edges.append({
                        "class_name": class_name,
                        "method_name": method,
                        "label": label,
                        "entry_ts_ns": entry_ts
                    })
        
        conn.commit()
        conn.close()
        
        # Write report
        with open(REPORT_PATH, 'w') as f:
            json.dump({
                "recovered_count": len(recovered_edges),
                "recovered_edges": recovered_edges
            }, f, indent=2)
            
        logger.info(f"DERP execution completed. Recovered {len(recovered_edges)} dynamic edges. Report saved to {REPORT_PATH}.")
    except Exception as e:
        logger.error(f"Error in DERP Engine: {e}")

if __name__ == '__main__':
    run_derp()
