"""
pipeline_graph.py  —  TraceRAG LangGraph Pipeline

Full end-to-end pipeline (Static Analysis + RAG Forensics) compiled as a
single LangGraph StateGraph.  Run it once for any sample_id and it executes
every stage automatically.

Stage 1 – Static Analysis (scripts/)
    extract_features     →  Decompile APKs (placed manually); extract permissions,
                            API calls, and strings → detailed_dataset.csv
    build_static_chunks  →  Convert detailed_dataset.csv → chunks.jsonl + SQLite
                            (bridges static pipeline into RAG pipeline format)

Stage 2 – RAG Forensics Pipeline
    ssaf_filter          →  Separate security-sensitive chunks from benign ones
    describer            →  LLM summarises every sensitive chunk
    qdrant_indexer       →  Embed + store chunks in local Qdrant vector DB
    forensic_queries     →  11 expert semantic queries + LLM-generated follow-ups
    prefetch_and_prune   →  Callgraph BFS + active-branch Jimple pruning
    llm_analyzer         →  Generate formal behavioural claims per call-chain
    verify_claims        →  Cross-check claims against strace (skipped if no strace)

Usage:
    python pipeline_graph.py              # sample_id defaults to 1
    python pipeline_graph.py 2            # run for sample 2

Note:
    Place your APK files manually in the data/apks/ directory before running.
    The pipeline picks them up from there automatically.
"""

import os
import sys
import subprocess
from typing import TypedDict
from loguru import logger
from langgraph.graph import StateGraph, START, END


# ── State schema ─────────────────────────────────────────────────────────────

class PipelineState(TypedDict):
    sample_id: int
    status: str
    message: str


# ── Helper ────────────────────────────────────────────────────────────────────

def _banner(title: str, sample_id: int) -> None:
    logger.info(f"\n{'=' * 54}")
    logger.info(f"  {title}  [sample {sample_id}]")
    logger.info(f"{'=' * 54}")


def _run(cmd: list, cwd: str | None = None) -> None:
    """Run a subprocess, raising CalledProcessError on failure."""
    subprocess.run(cmd, check=True, cwd=cwd)


SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "scripts")


# ════════════════════════════════════════════════════════════════════════════
# STAGE 1 — Static Analysis Nodes
# ════════════════════════════════════════════════════════════════════════════

def extract_features_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    _banner("Node: Extract Features", state["sample_id"])
    try:
        _run([sys.executable, "extract_features_detailed.py"], cwd=SCRIPTS_DIR)
        return {**state, "status": "FEATURES_EXTRACTED",
                "message": "Static features extracted (permissions, API calls, strings)."}
    except Exception as e:
        logger.error(f"extract_features failed: {e}")
        return {**state, "status": "FAILED", "message": f"extract_features failed: {e}"}


def build_static_chunks_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    _banner("Node: Build Static Chunks (bridge)", sample_id)
    try:
        _run([sys.executable, "build_static_chunks.py", str(sample_id)], cwd=SCRIPTS_DIR)
        return {**state, "status": "CHUNKS_BUILT",
                "message": "Static CSV converted to chunks.jsonl + SQLite DB."}
    except Exception as e:
        logger.error(f"build_static_chunks failed: {e}")
        return {**state, "status": "FAILED", "message": f"build_static_chunks failed: {e}"}


# ════════════════════════════════════════════════════════════════════════════
# STAGE 2 — RAG Forensics Nodes
# ════════════════════════════════════════════════════════════════════════════

def ssaf_filter_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    _banner("Node: SSAF Filter", sample_id)
    try:
        _run([sys.executable, "ssaf_filter.py", str(sample_id)])
        return {**state, "status": "SSAF_FILTERED",
                "message": "Sensitive and benign chunks separated by SSAF."}
    except Exception as e:
        logger.error(f"ssaf_filter failed: {e}")
        return {**state, "status": "FAILED", "message": f"ssaf_filter failed: {e}"}


def describer_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    _banner("Node: Describer (LLM Summarisation)", sample_id)
    try:
        _run([sys.executable, "describer.py", str(sample_id)])
        return {**state, "status": "SUMMARIZED",
                "message": "Sensitive chunks summarised by LLM."}
    except Exception as e:
        logger.error(f"describer failed: {e}")
        return {**state, "status": "FAILED", "message": f"describer failed: {e}"}


def qdrant_indexer_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    _banner("Node: Qdrant Indexer", sample_id)
    try:
        _run([sys.executable, "qdrant_indexer.py", str(sample_id)])
        return {**state, "status": "INDEXED",
                "message": "Chunks embedded and indexed in Qdrant."}
    except Exception as e:
        logger.error(f"qdrant_indexer failed: {e}")
        return {**state, "status": "FAILED", "message": f"qdrant_indexer failed: {e}"}


def forensic_queries_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    _banner("Node: Forensic Queries", sample_id)
    try:
        _run([sys.executable, "forensic_queries.py", str(sample_id)])
        return {**state, "status": "QUERIED",
                "message": "11 expert forensic queries + adaptive follow-ups executed."}
    except Exception as e:
        logger.error(f"forensic_queries failed: {e}")
        return {**state, "status": "FAILED", "message": f"forensic_queries failed: {e}"}


def prefetch_and_prune_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    _banner("Node: Prefetch & Prune", sample_id)
    try:
        _run([sys.executable, "prefetch_and_prune.py", str(sample_id)])
        return {**state, "status": "PRUNED",
                "message": "Callgraph BFS done; Jimple pruned to active branches."}
    except Exception as e:
        logger.error(f"prefetch_and_prune failed: {e}")
        return {**state, "status": "FAILED", "message": f"prefetch_and_prune failed: {e}"}


def llm_analyzer_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    _banner("Node: LLM Analyzer", sample_id)
    try:
        _run([sys.executable, "llm_analyzer.py", str(sample_id)])
        return {**state, "status": "ANALYZED",
                "message": "Formal behavioural claims generated by LLM."}
    except Exception as e:
        logger.error(f"llm_analyzer failed: {e}")
        return {**state, "status": "FAILED", "message": f"llm_analyzer failed: {e}"}


def verify_claims_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    _banner("Node: Verify Claims", sample_id)
    try:
        _run([sys.executable, "verify_claims.py", str(sample_id)])
        return {**state, "status": "SUCCESS",
                "message": "Claims verified (or flagged STATIC_ONLY if no strace). Pipeline complete."}
    except Exception as e:
        logger.error(f"verify_claims failed: {e}")
        return {**state, "status": "FAILED", "message": f"verify_claims failed: {e}"}


# ════════════════════════════════════════════════════════════════════════════
# Build and compile the LangGraph StateGraph
# ════════════════════════════════════════════════════════════════════════════

builder = StateGraph(PipelineState)

# Stage 1 — Static Analysis
builder.add_node("extract_features",     extract_features_node)
builder.add_node("build_static_chunks",  build_static_chunks_node)

# Stage 2 — RAG Forensics
builder.add_node("ssaf_filter",          ssaf_filter_node)
builder.add_node("describer",            describer_node)
builder.add_node("qdrant_indexer",       qdrant_indexer_node)
builder.add_node("forensic_queries",     forensic_queries_node)
builder.add_node("prefetch_and_prune",   prefetch_and_prune_node)
builder.add_node("llm_analyzer",         llm_analyzer_node)
builder.add_node("verify_claims",        verify_claims_node)

# Edges — Stage 1 (linear)
builder.add_edge(START,                  "extract_features")
builder.add_edge("extract_features",     "build_static_chunks")

# Bridge — Stage 1 → Stage 2
builder.add_edge("build_static_chunks",  "ssaf_filter")

# Edges — Stage 2 (linear)
builder.add_edge("ssaf_filter",          "describer")
builder.add_edge("describer",            "qdrant_indexer")
builder.add_edge("qdrant_indexer",       "forensic_queries")
builder.add_edge("forensic_queries",     "prefetch_and_prune")
builder.add_edge("prefetch_and_prune",   "llm_analyzer")
builder.add_edge("llm_analyzer",         "verify_claims")
builder.add_edge("verify_claims",        END)

# Compile once — reuse graph object for multiple runs
graph = builder.compile()


# ════════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sample_id = 1
    if len(sys.argv) > 1:
        try:
            sample_id = int(sys.argv[1])
        except ValueError:
            logger.warning("Invalid sample_id argument, defaulting to 1")

    logger.info("=" * 54)
    logger.info(f"  TraceRAG LangGraph Pipeline — Sample {sample_id}")
    logger.info("=" * 54)

    result = graph.invoke(
        {"sample_id": sample_id, "status": "STARTING", "message": "Initialising."}
    )

    logger.info(f"\n{'=' * 54}")
    logger.info(f"  Pipeline finished.")
    logger.info(f"  Final Status : {result.get('status')}")
    logger.info(f"  Message      : {result.get('message')}")
    logger.info(f"{'=' * 54}")
