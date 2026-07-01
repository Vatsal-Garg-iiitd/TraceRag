import json
import re
from huggingface_hub import InferenceClient
from loguru import logger

from config import HF_API_KEY, HF_MODEL_ID, path_in_project

import sys

if len(sys.argv) < 2:
    print("Usage: python describer.py <sample_id>")
    sys.exit(1)

SAMPLE_ID = int(sys.argv[1])
LOG_DIR = path_in_project(f"logs/sample_{SAMPLE_ID}")

SENSITIVE_PATH = LOG_DIR / "chunks_sensitive.jsonl"
SUMMARIZED_PATH = LOG_DIR / "summarized_chunks.jsonl"

SYSTEM_PROMPT_DESCRIBE = """\
You are an expert Android malware forensic analyst in a Tier-2 triage pipeline.

You receive SSAF-flagged methods: Jimple IR, kernel syscalls, and callee lists from a dynamic trace.

For each method, write one plain-text paragraph using this structure:
1. THREAT CLASSIFICATION — malware behavior type (dropper, C2, exfiltration, privilege escalation, etc.).
2. MALICIOUS INTENT — why this code is suspicious and what an attacker gains.
3. EVIDENCE — cite specific APIs and syscalls from the input only.
4. MITRE ATT&CK — closest Mobile technique ID and name when applicable.

Formatting rules:
- One line per method: Summary for <method_name>: <single paragraph>
- Plain text only: no markdown, bullets, or headings.
- Do not invent syscalls, classes, or behaviors absent from the input."""


def build_class_user_prompt(cname, methods):
    """Assemble user message with class-scoped trace data only."""
    sections = [
        f"Class: {cname}",
        f"Methods flagged by SSAF: {len(methods)}",
        "",
        "Produce a forensic summary for each method below.",
        "",
    ]
    for m in methods:
        sections.extend([
            f"--- Method: {m['method_name']} ---",
            f"Jimple IR:\n{m['raw_jimple']}",
            f"Kernel syscalls:\n{json.dumps(m['kernel_syscalls'], indent=2)}",
        ])
        if m.get("callees"):
            sections.append(f"Calls into: {m['callees']}")
        sections.append("")
    return "\n".join(sections)

def load_chunks(path):
    if not path.exists():
        return []
    with open(path, "r") as f:
        return [json.loads(line) for line in f if line.strip()]

def strip_markdown(text):
    """Remove markdown bold/italic markers and extra whitespace."""
    text = re.sub(r'\*\*', '', text)
    text = re.sub(r'\*', '', text)
    text = re.sub(r'#+\s*', '', text)
    return text.strip()

def extract_summary_for_method(result_text, method_name):
    """Robustly extract summary for a method from LLM output, handling markdown."""
    cleaned = strip_markdown(result_text)
    
    # Try to find "Summary for <method>:" pattern
    pattern = re.compile(
        rf'Summary\s+for\s+{re.escape(method_name)}\s*:\s*(.*?)(?=Summary\s+for\s+\w+\s*:|$)',
        re.IGNORECASE | re.DOTALL
    )
    match = pattern.search(cleaned)
    if match:
        summary = match.group(1).strip()
        if summary:
            return summary
    
    # Fallback: return the entire cleaned response
    return cleaned[:500]

def process_chunks():
    try:
        chunks = load_chunks(SENSITIVE_PATH)
        if not chunks:
            logger.info("No sensitive chunks to process.")
            return

        # Group by class
        class_clusters = {}
        for chunk in chunks:
            cname = chunk['class_name']
            class_clusters.setdefault(cname, []).append(chunk)

        client = InferenceClient(model=HF_MODEL_ID, token=HF_API_KEY)
        out_file = open(SUMMARIZED_PATH, 'w')

        for cname, methods in class_clusters.items():
            logger.info(f"Processing class cluster: {cname} with {len(methods)} methods")

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT_DESCRIBE},
                {"role": "user", "content": build_class_user_prompt(cname, methods)},
            ]

            try:
                response = client.chat_completion(messages, max_tokens=1000, temperature=0.1)
                result = response.choices[0].message.content
                logger.info(f"LLM raw response for {cname}:\n{result}")
            except Exception as e:
                logger.error(f"Error calling HF API for class {cname}: {e}")
                result = f"Error generating summary: {e}"

            # Parse summaries per method
            for m in methods:
                summary = extract_summary_for_method(result, m['method_name'])
                m['llm_summary'] = summary
                out_file.write(json.dumps(m) + '\n')
                logger.info(f"  Written summary for {m['method_name']}: {summary[:120]}...")

        out_file.close()
        logger.info("Summarization complete.")
    except Exception as e:
        logger.error(f"Error in process_chunks: {e}")

if __name__ == '__main__':
    process_chunks()
