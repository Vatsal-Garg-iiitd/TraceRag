import os
import sys
import subprocess
import shutil
from typing import TypedDict
from loguru import logger
from langgraph.graph import StateGraph, START, END

# Define the state schema
class PipelineState(TypedDict):
    sample_id: int
    status: str
    message: str

def setup_data_node(state: PipelineState) -> PipelineState:
    sample_id = state["sample_id"]
    logger.info(f"\n==================================================")
    logger.info(f"--- [Node: Setup Data] Mocking Telemetry for Sample {sample_id} ---")
    logger.info(f"==================================================")
    try:
        # Run mock_module1_data.py to generate DB and log files
        subprocess.run([sys.executable, "mock_module1_data.py"], check=True)
        
        # Create logs/sample_{SAMPLE_ID} directory and move logs
        log_dir = f"logs/sample_{sample_id}"
        os.makedirs(log_dir, exist_ok=True)
        
        if os.path.exists("logs/jvmti_trace.log"):
            shutil.move("logs/jvmti_trace.log", f"{log_dir}/jvmti_trace.log")
        if os.path.exists("logs/strace.log"):
            shutil.move("logs/strace.log", f"{log_dir}/strace.log")
            
        logger.info(f"Mock JVMTI and strace telemetry placed in {log_dir}")
        return {**state, "status": "SETUP_COMPLETE", "message": "Mock data generated and structured."}
    except Exception as e:
        logger.error(f"Setup data failed: {e}")
        return {**state, "status": "FAILED", "message": f"Setup data failed: {str(e)}"}

def build_chunks_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    logger.info(f"\n==================================================")
    logger.info(f"--- [Node: Build Chunks] Trace Alignment for Sample {sample_id} ---")
    logger.info(f"==================================================")
    try:
        subprocess.run([sys.executable, "build_chunks.py", str(sample_id)], check=True)
        return {**state, "status": "CHUNKS_BUILT", "message": "Chunks successfully built."}
    except Exception as e:
        logger.error(f"Build chunks failed: {e}")
        return {**state, "status": "FAILED", "message": f"Build chunks failed: {str(e)}"}

def ssaf_filter_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    logger.info(f"\n==================================================")
    logger.info(f"--- [Node: SSAF Filter] Security API Filtering for Sample {sample_id} ---")
    logger.info(f"==================================================")
    try:
        subprocess.run([sys.executable, "ssaf_filter.py", str(sample_id)], check=True)
        return {**state, "status": "SSAF_FILTERED", "message": "Sensitive and benign chunks separated."}
    except Exception as e:
        logger.error(f"SSAF filter failed: {e}")
        return {**state, "status": "FAILED", "message": f"SSAF filter failed: {str(e)}"}

def describer_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    logger.info(f"\n==================================================")
    logger.info(f"--- [Node: Describer] LLM Summarization for Sample {sample_id} ---")
    logger.info(f"==================================================")
    try:
        subprocess.run([sys.executable, "describer.py", str(sample_id)], check=True)
        return {**state, "status": "SUMMARIZED", "message": "Sensitive chunks summarized by LLM."}
    except Exception as e:
        logger.error(f"Describer failed: {e}")
        return {**state, "status": "FAILED", "message": f"Describer failed: {str(e)}"}

def qdrant_indexer_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    logger.info(f"\n==================================================")
    logger.info(f"--- [Node: Qdrant Indexer] Semantic Indexing for Sample {sample_id} ---")
    logger.info(f"==================================================")
    try:
        subprocess.run([sys.executable, "qdrant_indexer.py", str(sample_id)], check=True)
        return {**state, "status": "INDEXED", "message": "Chunks indexed in Qdrant."}
    except Exception as e:
        logger.error(f"Qdrant Indexer failed: {e}")
        return {**state, "status": "FAILED", "message": f"Qdrant Indexer failed: {str(e)}"}

def forensic_queries_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    logger.info(f"\n==================================================")
    logger.info(f"--- [Node: Forensic Queries] Vector Search & Triage for Sample {sample_id} ---")
    logger.info(f"==================================================")
    try:
        subprocess.run([sys.executable, "forensic_queries.py", str(sample_id)], check=True)
        return {**state, "status": "QUERIED", "message": "Forensic expert queries executed."}
    except Exception as e:
        logger.error(f"Forensic Queries failed: {e}")
        return {**state, "status": "FAILED", "message": f"Forensic Queries failed: {str(e)}"}

def prefetch_and_prune_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    logger.info(f"\n==================================================")
    logger.info(f"--- [Node: Prefetch & Prune] Callgraph Context Assembly for Sample {sample_id} ---")
    logger.info(f"==================================================")
    try:
        subprocess.run([sys.executable, "prefetch_and_prune.py", str(sample_id)], check=True)
        return {**state, "status": "PRUNED", "message": "Call graph prefetched and Jimple pruned."}
    except Exception as e:
        logger.error(f"Prefetch & Prune failed: {e}")
        return {**state, "status": "FAILED", "message": f"Prefetch & Prune failed: {str(e)}"}

def llm_analyzer_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    logger.info(f"\n==================================================")
    logger.info(f"--- [Node: LLM Analyzer] Forensic Reasoning for Sample {sample_id} ---")
    logger.info(f"==================================================")
    try:
        subprocess.run([sys.executable, "llm_analyzer.py", str(sample_id)], check=True)
        return {**state, "status": "ANALYZED", "message": "Behavioral claims generated."}
    except Exception as e:
        logger.error(f"LLM Analyzer failed: {e}")
        return {**state, "status": "FAILED", "message": f"LLM Analyzer failed: {str(e)}"}

def verify_claims_node(state: PipelineState) -> PipelineState:
    if state["status"] == "FAILED":
        return state
    sample_id = state["sample_id"]
    logger.info(f"\n==================================================")
    logger.info(f"--- [Node: Verify Claims] Claim Verification against Syscalls for Sample {sample_id} ---")
    logger.info(f"==================================================")
    try:
        subprocess.run([sys.executable, "verify_claims.py", str(sample_id)], check=True)
        return {**state, "status": "SUCCESS", "message": "Claims verified against strace logs. Pipeline complete."}
    except Exception as e:
        logger.error(f"Verify Claims failed: {e}")
        return {**state, "status": "FAILED", "message": f"Verify Claims failed: {str(e)}"}

# Build StateGraph
builder = StateGraph(PipelineState)

# Add nodes
builder.add_node("setup_data", setup_data_node)
builder.add_node("build_chunks", build_chunks_node)
builder.add_node("ssaf_filter", ssaf_filter_node)
builder.add_node("describer", describer_node)
builder.add_node("qdrant_indexer", qdrant_indexer_node)
builder.add_node("forensic_queries", forensic_queries_node)
builder.add_node("prefetch_and_prune", prefetch_and_prune_node)
builder.add_node("llm_analyzer", llm_analyzer_node)
builder.add_node("verify_claims", verify_claims_node)

# Set up edges
builder.add_edge(START, "setup_data")
builder.add_edge("setup_data", "build_chunks")
builder.add_edge("build_chunks", "ssaf_filter")
builder.add_edge("ssaf_filter", "describer")
builder.add_edge("describer", "qdrant_indexer")
builder.add_edge("qdrant_indexer", "forensic_queries")
builder.add_edge("forensic_queries", "prefetch_and_prune")
builder.add_edge("prefetch_and_prune", "llm_analyzer")
builder.add_edge("llm_analyzer", "verify_claims")
builder.add_edge("verify_claims", END)

# Compile the graph
graph = builder.compile()

if __name__ == "__main__":
    # Allow target sample_id as argument, default to 1
    sample_id = 1
    if len(sys.argv) > 1:
        try:
            sample_id = int(sys.argv[1])
        except ValueError:
            logger.warning("Invalid sample_id argument, defaulting to 1")

    logger.info("==================================================")
    logger.info(f"Compiling and running LangGraph pipeline for Sample {sample_id}...")
    logger.info("==================================================")
    
    initial_state = {"sample_id": sample_id, "status": "STARTING", "message": "Initializing execution."}
    result = graph.invoke(initial_state)
    
    logger.info(f"\n==================================================")
    logger.info(f"LangGraph execution finished.")
    logger.info(f"Final Status: {result.get('status')}")
    logger.info(f"Message: {result.get('message')}")
    logger.info("==================================================")
