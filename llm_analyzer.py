import json
import re
from huggingface_hub import InferenceClient
from loguru import logger
from langsmith import traceable

from config import HF_API_KEY, HF_MODEL_ID, path_in_project, setup_langsmith_tracing

setup_langsmith_tracing()

import sys

if len(sys.argv) < 2:
    print("Usage: python llm_analyzer.py <sample_id>")
    sys.exit(1)

SAMPLE_ID = int(sys.argv[1])
LOG_DIR = path_in_project(f"logs/sample_{SAMPLE_ID}")

CONTEXTS_PATH = LOG_DIR / "pruned_context.json"
OUTPUT_PATH = LOG_DIR / "behavioral_claims.json"

@traceable(name="call_llm_for_claims", run_type="llm")
def analyze_call_chain(client, chain_text):
    """Feeds pruned call-chain context to the LLM to generate formal behavioral claims."""
    system_prompt = (
        "You are an expert Android malware forensic analyst operating in a sandboxed analysis pipeline.\n"
        "Your task is to analyze the provided method-trace call chain context and generate formal behavioral claims.\n\n"
        "Generate a formal claim for each distinct suspicious or malicious behavior you identify.\n"
        "Output ONLY a raw JSON array of claim objects. No markdown, no conversational preambles or postambles, "
        "no explanation. Output raw JSON ONLY."
    )
    
    user_prompt = (
        f"Analyze the following Android call-chain context for malicious behavior:\n\n"
        f"=== CALL-CHAIN CONTEXT ===\n{chain_text}\n\n"
        f"For each distinct malicious or suspicious behavioral chain identified, generate a JSON object with "
        f"the following exact schema:\n"
        f"{{\n"
        f"  \"CLAIM_ID\": \"CLAIM_001\",\n"
        f"  \"BEHAVIOR\": \"Detailed explanation of the behavior\",\n"
        f"  \"EVIDENCE_CHAIN\": [\"com.package.Class.method1\", \"com.package.Class.method2\"],\n"
        f"  \"SYSCALL_EVIDENCE\": [\n"
        f"    {{\"syscall\": \"openat\", \"args_contains\": \"payload.key\"}},\n"
        f"    {{\"syscall\": \"execve\", \"args_contains\": \"su\"}}\n"
        f"  ],\n"
        f"  \"MITRE_TECHNIQUE\": \"T1059.001 - Command and Scripting Interpreter\",\n"
        f"  \"CONFIDENCE\": \"HIGH\",\n"
        f"  \"TEMPORAL_WINDOW\": {{\n"
        f"    \"start_ns\": <min_entry_timestamp_ns>,\n"
        f"    \"end_ns\": <max_exit_timestamp_ns>\n"
        f"  }},\n"
        f"  \"THREAD_ID\": <thread_id_integer>\n"
        f"}}\n\n"
        f"Ensure that 'TEMPORAL_WINDOW' start_ns and end_ns are exact integer nanosecond values from the trace.\n"
        f"Ensure that 'SYSCALL_EVIDENCE' lists the exact syscalls in lowercase (e.g., 'openat', 'execve', 'write', 'connect') "
        f"along with a key substring in their arguments that proves the behavior.\n"
        f"Return ONLY a JSON array containing these claim objects."
    )
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]
    
    try:
        response = client.chat_completion(messages, max_tokens=1500, temperature=0.1)
        content = response.choices[0].message.content.strip()
        logger.info(f"LLM Raw Claims Response:\n{content}")
        return content
    except Exception as e:
        logger.error(f"Error calling LLM for behavioral analysis: {e}")
        return ""

def run_analyzer():
    try:
        if not CONTEXTS_PATH.exists():
            logger.error(f"pruned_context.json not found at {CONTEXTS_PATH}")
            return
            
        with open(CONTEXTS_PATH, 'r') as f:
            contexts = json.load(f)
            
        if not contexts:
            logger.info("No contexts to analyze.")
            return
            
        hf_client = InferenceClient(model=HF_MODEL_ID, token=HF_API_KEY)
        all_claims = []
        claim_counter = 1
        
        # We only need to analyze suspect methods associated with malicious activity.
        # To avoid massive redundant LLM calls and context explosion, let's group by thread_id or select seed methods
        for seed_fqn, context in contexts.items():
            # Skip pure benign seeds to save LLM throughput
            if "com.benign" in seed_fqn:
                logger.info(f"Skipping benign seed method: {seed_fqn}")
                continue
                
            logger.info(f"Analyzing call-chain context for seed: {seed_fqn}")
            
            # Format chain details for prompt
            chain_lines = []
            chain_methods = context.get("call_chain", {})
            for m_fqn, m_data in chain_methods.items():
                if "com.benign" in m_fqn:
                    continue  # Filter out benign helpers in the malicious chain representation
                chain_lines.append(f"Method: {m_fqn}")
                chain_lines.append(f"  Thread ID: {m_data.get('thread_id')}")
                chain_lines.append(f"  Time Window: {m_data.get('entry_ts_ns')} -> {m_data.get('exit_ts_ns')}")
                chain_lines.append(f"  Pruned Jimple:\n{m_data.get('pruned_jimple')}")
                chain_lines.append(f"  Syscalls: {json.dumps(m_data.get('kernel_syscalls'))}")
                chain_lines.append(f"  JNI calls: {m_data.get('native_jni')}")
                chain_lines.append(f"  DERP Recovered branch labels: {m_data.get('derp_recovered_labels')}")
                chain_lines.append("-" * 30)
                
            chain_text = "\n".join(chain_lines)
            
            # Call LLM
            llm_output = analyze_call_chain(hf_client, chain_text)
            
            # Parse claims
            try:
                # Regex to isolate JSON array from markdown/text if LLM included it
                json_match = re.search(r'\[\s*\{.*\}\s*\]', llm_output, re.DOTALL)
                if json_match:
                    llm_output = json_match.group(0)
                    
                claims_list = json.loads(llm_output)
                if isinstance(claims_list, list):
                    for claim in claims_list:
                        # Normalize claim ID
                        claim["CLAIM_ID"] = f"CLAIM_{claim_counter:03d}"
                        all_claims.append(claim)
                        claim_counter += 1
                        logger.info(f"  Successfully loaded claim: {claim['CLAIM_ID']} - {claim['BEHAVIOR'][:80]}...")
            except Exception as e:
                logger.error(f"  Failed to parse LLM claims list for {seed_fqn}: {e}")
                
        # Save claims
        with open(OUTPUT_PATH, 'w') as f:
            json.dump(all_claims, f, indent=2)
            
        logger.info(f"LLM Behavioral Analysis complete. Saved {len(all_claims)} behavioral claims to {OUTPUT_PATH}")
    except Exception as e:
        logger.error(f"Error in LLM Analyzer: {e}")

if __name__ == '__main__':
    run_analyzer()
