import sqlite3
import json
import re
import networkx as nx
from qdrant_client import QdrantClient
from loguru import logger

from config import QDRANT_COLLECTION, path_in_project

import sys

if len(sys.argv) < 2:
    print("Usage: python prefetch_and_prune.py <sample_id>")
    sys.exit(1)

SAMPLE_ID = int(sys.argv[1])
LOG_DIR = path_in_project(f"logs/sample_{SAMPLE_ID}")

DB_PATH = path_in_project("pipeline.db")
FINDINGS_PATH = LOG_DIR / "expert_findings.json"
OUTPUT_PATH = LOG_DIR / "pruned_context.json"
COLLECTION_NAME = QDRANT_COLLECTION
QDRANT_PATH = path_in_project("qdrant_storage")

def prefetch_neighbors(G, seed_method, depth=2):
    """BFS traversal up to depth 2 in both successors and predecessors directions."""
    neighbors = {seed_method}
    
    # Forward depth 2 (callees)
    current = {seed_method}
    for _ in range(depth):
        next_level = set()
        for node in current:
            if node in G:
                next_level.update(G.successors(node))
        neighbors.update(next_level)
        current = next_level
        
    # Backward depth 2 (callers)
    current = {seed_method}
    for _ in range(depth):
        next_level = set()
        for node in current:
            if node in G:
                next_level.update(G.predecessors(node))
        neighbors.update(next_level)
        current = next_level
        
    return list(neighbors)

def prune_jimple(jimple_text, active_labels):
    """
    Remove lines belonging to unexecuted CFG branches.
    If no label markers are found, returns the original text.
    """
    if not active_labels:
        return jimple_text[:1500]
        
    lines = jimple_text.splitlines()
    kept = []
    keep = True
    has_labels = False
    
    for line in lines:
        stripped = line.strip()
        # Check if line is a label (ends with colon, not a signature or special statement)
        if (stripped.endswith(':') or re.match(r'^[a-zA-Z0-9_]+:$', stripped)) and not stripped.startswith('public') and not stripped.startswith('private') and not stripped.startswith('specialinvoke') and not stripped.startswith('virtualinvoke'):
            has_labels = True
            label = stripped[:-1].strip()
            if label not in active_labels:
                keep = False
            else:
                keep = True
        if keep:
            kept.append(line)
            
    if not has_labels:
        return jimple_text  # Fallback: no labels found, keep everything
        
    return '\n'.join(kept)

def run_prefetch_and_prune():
    try:
        logger.info("Connecting to SQLite pipeline database...")
        conn = sqlite3.connect(DB_PATH)
        
        # 1. Build Call-Graph DiGraph via NetworkX
        logger.info("Building call-graph DiGraph...")
        G = nx.DiGraph()
        for row in conn.execute('SELECT caller, callee FROM callgraph'):
            G.add_edge(row[0], row[1])
            
        # Load expert findings
        if not os.path.exists(FINDINGS_PATH):
            logger.error(f"expert_findings.json not found at {FINDINGS_PATH}")
            return
            
        with open(FINDINGS_PATH, 'r') as f:
            expert_data = json.load(f)
            
        suspect_methods = expert_data.get("all_suspect_methods", [])
        logger.info(f"Loaded {len(suspect_methods)} suspect seed methods.")
        
        # 2. Batch scroll Qdrant collection to map all points
        logger.info("Connecting to local Qdrant for batch pre-fetching...")
        qdrant = QdrantClient(path=str(QDRANT_PATH))
        
        res = qdrant.scroll(
            collection_name=COLLECTION_NAME,
            limit=100,
            with_payload=True
        )
        points = res[0]
        
        # Map class_name.method_name -> payload
        chunks_map = {}
        for p in points:
            payload = p.payload
            fqn = f"{payload.get('class_name')}.{payload.get('method_name')}"
            chunks_map[fqn] = payload
            
        logger.info(f"Loaded {len(chunks_map)} execution chunks from Qdrant.")
        
        pruned_contexts = {}
        
        # 3. Process each suspect method
        for suspect in suspect_methods:
            logger.info(f"Processing call-graph prefetching for seed method: {suspect}")
            
            # Prefetch neighbors up to depth 2
            neighbors = prefetch_neighbors(G, suspect, depth=2)
            logger.info(f"  Seed {suspect} has {len(neighbors)} prefetched neighbors in call chain.")
            
            call_chain_context = {}
            for neighbor_fqn in neighbors:
                # Fetch payload from Qdrant map
                payload = chunks_map.get(neighbor_fqn)
                if not payload:
                    logger.warning(f"  No execution trace payload found in Qdrant for {neighbor_fqn}")
                    continue
                    
                # Fetch dynamic DERP labels from SQLite
                class_name, method_name = neighbor_fqn.rsplit('.', 1)
                derp_rows = conn.execute(
                    'SELECT label, ts FROM dynamic_edges WHERE class=? AND method=?',
                    (class_name, method_name)
                ).fetchall()
                
                derp_labels = [row[0] for row in derp_rows]
                
                # Dynamic executed branch labels
                executed_cfg = payload.get('executed_cfg', [])
                
                # Active Path Pruning
                pruned_jim = prune_jimple(payload.get('raw_jimple', ''), executed_cfg)
                
                call_chain_context[neighbor_fqn] = {
                    "class_name": class_name,
                    "method_name": method_name,
                    "pruned_jimple": pruned_jim,
                    "kernel_syscalls": payload.get('kernel_syscalls', []),
                    "native_jni": payload.get('native_jni', []),
                    "executed_cfg": executed_cfg,
                    "derp_recovered_labels": derp_labels,
                    "thread_id": payload.get('thread_id', 0),
                    "entry_ts_ns": payload.get('entry_ts_ns', 0),
                    "exit_ts_ns": payload.get('exit_ts_ns', 0),
                    "ssaf_flagged": payload.get('ssaf_flagged', False),
                    "summary": payload.get('summary', '')
                }
                
            # If seed has a payload, store the details
            seed_payload = chunks_map.get(suspect)
            if seed_payload:
                pruned_contexts[suspect] = {
                    "seed_method": suspect,
                    "pruned_jimple": prune_jimple(seed_payload.get('raw_jimple', ''), seed_payload.get('executed_cfg', [])),
                    "active_labels": seed_payload.get('executed_cfg', []),
                    "call_chain": call_chain_context
                }
                
        # 4. Save contexts
        with open(OUTPUT_PATH, 'w') as f:
            json.dump(pruned_contexts, f, indent=2)
            
        conn.close()
        logger.info(f"Prefetch & Prune complete. Saved {len(pruned_contexts)} pruned call chains to {OUTPUT_PATH}")
    except Exception as e:
        logger.error(f"Error in prefetch and prune: {e}")

if __name__ == '__main__':
    run_prefetch_and_prune()
