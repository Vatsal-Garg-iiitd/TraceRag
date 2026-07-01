import json
import re
from loguru import logger

from config import path_in_project

import sys

if len(sys.argv) < 2:
    print("Usage: python verify_claims.py <sample_id>")
    sys.exit(1)

SAMPLE_ID = int(sys.argv[1])
LOG_DIR = path_in_project(f"logs/sample_{SAMPLE_ID}")

STRACE_PATH = LOG_DIR / "strace.log"
CLAIMS_PATH = LOG_DIR / "behavioral_claims.json"
OUTPUT_PATH = LOG_DIR / "verified_claims.json"

SYSCALL_RE = re.compile(
    r'(\d+)\s+([\d.]+)\s+(\w+)\((.*)\)\s+=\s+(.+)'
)

def parse_strace():
    events = []
    if not STRACE_PATH.exists():
        logger.error(f"strace.log not found at {STRACE_PATH}")
        return events
        
    for line in open(STRACE_PATH, errors="ignore"):
        m = SYSCALL_RE.match(line.strip())
        if m:
            events.append({
                'tid':     int(m.group(1)),
                'ts_ns':   int(float(m.group(2)) * 1e9),
                'syscall': m.group(3),
                'args':    m.group(4),
                'retval':  m.group(5).strip(),
                'raw_line': line.strip()
            })
    return events

def run_verification():
    try:
        logger.info("Parsing raw strace log...")
        strace_events = parse_strace()
        logger.info(f"Loaded {len(strace_events)} ground-truth syscall events from strace.log.")

        # No strace data (Layer 1 not used) — write a skipped report and exit gracefully
        if not strace_events:
            logger.warning("No strace events found. Layer 1 (dynamic sandbox) was not used.")
            logger.warning("Skipping syscall-level claim verification. Writing STATIC_ONLY verdict.")
            skipped_output = {
                "faith_score": None,
                "mode": "STATIC_ONLY",
                "note": "Claim verification skipped — no strace.log (Layer 1 not used).",
                "summary": {"total_claims": 0, "verified": 0, "partial": 0, "unverified": 0},
                "verified_claims": []
            }
            with open(OUTPUT_PATH, "w") as f:
                json.dump(skipped_output, f, indent=2)
            logger.info(f"Skipped verification report saved to {OUTPUT_PATH}")
            return

        if not CLAIMS_PATH.exists():
            logger.error(f"behavioral_claims.json not found at {CLAIMS_PATH}")
            return
            
        with open(CLAIMS_PATH, 'r') as f:
            claims = json.load(f)
            
        logger.info(f"Loaded {len(claims)} behavioral claims from LLM Analyzer.")
        
        verified_count = 0
        partial_count = 0
        unverified_count = 0
        verified_claims = []
        
        for claim in claims:
            claim_id = claim.get("CLAIM_ID")
            behavior = claim.get("BEHAVIOR")
            tid = claim.get("THREAD_ID")
            window = claim.get("TEMPORAL_WINDOW", {})
            start_ns = window.get("start_ns", 0)
            end_ns = window.get("end_ns", 0)
            syscall_evidence = claim.get("SYSCALL_EVIDENCE", [])
            
            logger.info(f"Verifying {claim_id}: {behavior[:70]}...")
            
            claim_verified = False
            claim_partial = False
            best_verdict = "UNVERIFIED"
            
            condition_logs = []
            matched_strace_lines = []
            
            for evidence in syscall_evidence:
                cited_sys = evidence.get("syscall", "").lower()
                args_contains = evidence.get("args_contains", "")
                
                # Condition 1: Syscall Existence in strace
                # Robust matching: check if cited syscall is substring of trace syscall, and matches args
                matching_events = [
                    s for s in strace_events
                    if cited_sys in s['syscall'].lower() and args_contains.lower() in s['args'].lower()
                ]
                
                cond1_pass = len(matching_events) > 0
                cond2_pass = False
                cond3_pass = False
                
                if cond1_pass:
                    # Condition 2: Thread ID Match
                    tid_matched = [s for s in matching_events if s['tid'] == tid]
                    cond2_pass = len(tid_matched) > 0
                    
                    if cond2_pass:
                        # Condition 3: Temporal Containment
                        temporally_matched = [
                            s for s in tid_matched
                            if start_ns <= s['ts_ns'] <= end_ns
                        ]
                        cond3_pass = len(temporally_matched) > 0
                        
                        if cond3_pass:
                            matched_strace_lines.extend([s['raw_line'] for s in temporally_matched])
                
                # Map verdict for this specific evidence item
                if cond1_pass and cond2_pass and cond3_pass:
                    evidence_verdict = "VERIFIED"
                    claim_verified = True
                elif cond1_pass:
                    evidence_verdict = "PARTIAL"
                    claim_partial = True
                else:
                    evidence_verdict = "UNVERIFIED"
                    
                condition_logs.append({
                    "evidence_cited": evidence,
                    "verdict": evidence_verdict,
                    "checks": {
                        "syscall_exists": cond1_pass,
                        "tid_match": cond2_pass,
                        "temporal_containment": cond3_pass
                    }
                })
                
            # Determine overall claim verdict
            if claim_verified:
                final_verdict = "VERIFIED"
                verified_count += 1
            elif claim_partial:
                final_verdict = "PARTIAL"
                partial_count += 1
            else:
                final_verdict = "UNVERIFIED"
                unverified_count += 1
                
            verified_claims.append({
                "CLAIM_ID": claim_id,
                "BEHAVIOR": behavior,
                "EVIDENCE_CHAIN": claim.get("EVIDENCE_CHAIN", []),
                "MITRE_TECHNIQUE": claim.get("MITRE_TECHNIQUE", ""),
                "CONFIDENCE": claim.get("CONFIDENCE", ""),
                "THREAD_ID": tid,
                "TEMPORAL_WINDOW": window,
                "VERDICT": final_verdict,
                "matched_strace_lines": list(set(matched_strace_lines)),
                "evidence_verification_details": condition_logs
            })
            
            logger.info(f"  Verdict for {claim_id}: {final_verdict}")
            
        # Calculate Faith Score F_faith
        f_faith = verified_count / max(1, len(claims))
        
        output_payload = {
            "faith_score": f_faith,
            "summary": {
                "total_claims": len(claims),
                "verified": verified_count,
                "partial": partial_count,
                "unverified": unverified_count
            },
            "verified_claims": verified_claims
        }
        
        with open(OUTPUT_PATH, 'w') as f:
            json.dump(output_payload, f, indent=2)
            
        logger.info("=" * 60)
        logger.info(f"VERIFICATION PIPELINE SUMMARY:")
        logger.info(f"  Total Claims Evaluated: {len(claims)}")
        logger.info(f"  VERIFIED (All 3 Conditions Pass): {verified_count}")
        logger.info(f"  PARTIAL (Syscall exists but TID/Time mismatch): {partial_count}")
        logger.info(f"  UNVERIFIED (Hallucinated Syscall): {unverified_count}")
        logger.info(f"  Faithfulness Score (F_faith): {f_faith:.4f} (Target: >= 0.98)")
        logger.info(f"Verified Claims report saved to {OUTPUT_PATH}")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"Error in claim verification: {e}")

if __name__ == '__main__':
    run_verification()
