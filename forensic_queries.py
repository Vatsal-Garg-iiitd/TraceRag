import sys
import json
import re
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue
from huggingface_hub import InferenceClient
from loguru import logger
from langsmith import traceable

from config import (
    HF_API_KEY,
    HF_MODEL_ID,
    QDRANT_COLLECTION,
    path_in_project,
    setup_langsmith_tracing,
)

setup_langsmith_tracing()

if len(sys.argv) < 2:
    print("Usage: python forensic_queries.py <sample_id>")
    sys.exit(1)

SAMPLE_ID = int(sys.argv[1])
LOG_DIR = path_in_project(f"logs/sample_{SAMPLE_ID}")

COLLECTION_NAME = QDRANT_COLLECTION
OUTPUT_PATH = LOG_DIR / "expert_findings.json"
QDRANT_PATH = path_in_project("qdrant_storage")

EXPERT_QUERIES = [
    ("dynamic_class_loading", "Dynamic class loading via DexClassLoader or PathClassLoader for payload staging"),
    ("native_jni", "Native JNI code execution through System.loadLibrary or dlopen for code injection"),
    ("cryptographic_ops", "AES or DES cryptographic operations used to decrypt hidden payloads"),
    ("socket_c2", "Socket connection to external C2 server for command and control communication"),
    ("sms_fraud", "SMS sending via SmsManager for premium rate fraud or data exfiltration"),
    ("file_write_persistence", "File write operations to system directories for rootkit persistence"),
    ("privilege_escalation", "Runtime.exec or ProcessBuilder usage for privilege escalation via su"),
    ("boot_receiver", "Boot receiver registration for malware persistence across device restarts"),
    ("reflection_bypass", "Reflection-based method invocation to bypass security restrictions"),
    ("content_provider", "Content provider access for stealing contacts, SMS, or call logs"),
    ("http_post_exfil", "HTTP POST request containing device identifiers like IMEI or IMSI")
]

SYSTEM_PROMPT_FOLLOWUP = """\
You are a mobile malware forensic triage assistant for a vector-search pipeline.

Context: An analyst has run 11 category-based semantic searches over execution-trace chunks from a suspected malicious Android app. You receive a summary of top matches per category.

Your job:
- Identify security-sensitive gaps or under-explored patterns not fully covered by the initial queries (e.g. cross-thread sequencing, file write + network combo, anti-analysis, staging + exfil chains).
- Propose up to 3 new natural-language search queries optimized for dense retrieval over method-level trace summaries.

Query quality rules:
- Each query must be specific, forensic, and actionable (name APIs, behaviors, or artifact types where possible).
- Do not repeat or lightly rephrase an already-covered category from the summary.
- Prefer queries that would surface evidence the initial round likely missed.

Output format:
- Return ONLY a raw JSON array of strings, length 0–3.
- Example: ["query one", "query two"]
- No markdown, no explanations, no keys other than the string list."""


@traceable(name="call_llm_for_followup", run_type="llm")
def get_adaptive_queries(client, findings_summary):
    """Call LLM to generate up to 3 follow-up queries based on initial findings."""
    user_prompt = (
        "Initial forensic query results (one top match per category):\n\n"
        f"{findings_summary}\n\n"
        "Generate up to 3 follow-up vector-search queries for gaps or weakly covered behaviors."
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_FOLLOWUP},
        {"role": "user", "content": user_prompt},
    ]
    
    try:
        response = client.chat_completion(messages, max_tokens=300, temperature=0.1)
        content = response.choices[0].message.content.strip()
        logger.info(f"LLM Follow-up Query raw response: {content}")
        
        # Robust JSON extraction
        json_match = re.search(r'\[\s*".*?"\s*\]', content, re.DOTALL)
        if json_match:
            content = json_match.group(0)
            
        queries = json.loads(content)
        if isinstance(queries, list):
            return [str(q) for q in queries[:3]]
    except Exception as e:
        logger.error(f"Error calling LLM for follow-up queries: {e}")
        
    return []

@traceable(name="forensic_expert_query_engine", run_type="chain")
def run_forensic_pipeline():
    sample_filter = Filter(must=[FieldCondition(key="sample_id", match=MatchValue(value=SAMPLE_ID))])
    try:
        logger.info("Connecting to Qdrant collection...")
        client = QdrantClient(path=str(QDRANT_PATH))
        
        logger.info("Loading sentence-transformer model...")
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        hf_client = InferenceClient(model=HF_MODEL_ID, token=HF_API_KEY)
        
        findings = []
        unique_methods = set()
        findings_summary_lines = []
        
        logger.info("Executing 11 Expert Forensic Queries...")
        for category, query_text in EXPERT_QUERIES:
            vector = model.encode(query_text).tolist()
            
            # Query Qdrant using query_points with metadata filter
            res = client.query_points(
                collection_name=COLLECTION_NAME,
                query=vector,
                query_filter=sample_filter,
                limit=5
            )
            results = res.points
            
            matches = []
            for r in results:
                payload = r.payload
                method_fqn = f"{payload.get('class_name')}.{payload.get('method_name')}"
                unique_methods.add(method_fqn)
                
                matches.append({
                    "class_name": payload.get("class_name"),
                    "method_name": payload.get("method_name"),
                    "score": float(r.score),
                    "ssaf_flagged": payload.get("ssaf_flagged"),
                    "summary_snippet": payload.get("summary")[:150] + "..." if payload.get("summary") else ""
                })
            
            findings.append({
                "category": category,
                "query": query_text,
                "matches": matches
            })
            
            if matches:
                top_match = matches[0]
                findings_summary_lines.append(
                    f"- Category '{category}': top match is {top_match['class_name']}.{top_match['method_name']} "
                    f"(Score: {top_match['score']:.3f}, SSAF: {top_match['ssaf_flagged']})"
                )
        
        findings_summary = "\n".join(findings_summary_lines)
        logger.info(f"Initial Queries Summary:\n{findings_summary}")
        
        # Layer 3.1: Adaptive Follow-Up Query Round
        logger.info("Generating Adaptive Follow-Up Queries via LLM...")
        followup_queries = get_adaptive_queries(hf_client, findings_summary)
        logger.info(f"Generated follow-up queries: {followup_queries}")
        
        followup_results = []
        for q in followup_queries:
            vector = model.encode(q).tolist()
            res = client.query_points(
                collection_name=COLLECTION_NAME,
                query=vector,
                query_filter=sample_filter,
                limit=3
            )
            results = res.points
            
            matches = []
            for r in results:
                payload = r.payload
                method_fqn = f"{payload.get('class_name')}.{payload.get('method_name')}"
                unique_methods.add(method_fqn)
                
                matches.append({
                    "class_name": payload.get("class_name"),
                    "method_name": payload.get("method_name"),
                    "score": float(r.score),
                    "ssaf_flagged": payload.get("ssaf_flagged"),
                    "summary_snippet": payload.get("summary")[:150] + "..." if payload.get("summary") else ""
                })
            
            followup_results.append({
                "query": q,
                "matches": matches
            })
            
        output_payload = {
            "expert_findings": findings,
            "adaptive_followup": followup_results,
            "all_suspect_methods": list(unique_methods)
        }
        
        with open(OUTPUT_PATH, 'w') as f:
            json.dump(output_payload, f, indent=2)
            
        logger.info(f"Forensic Expert Query complete. Saved findings to {OUTPUT_PATH}. Found {len(unique_methods)} suspect methods.")
    except Exception as e:
        logger.error(f"Error running forensic query pipeline: {e}")

if __name__ == '__main__':
    run_forensic_pipeline()
