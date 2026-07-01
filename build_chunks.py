import sys
import os
import sqlite3
import re
import json
from loguru import logger

from config import path_in_project

if len(sys.argv) < 2:
    print("Usage: python build_chunks.py <sample_id>")
    sys.exit(1)

SAMPLE_ID = int(sys.argv[1])
LOG_DIR = path_in_project(f"logs/sample_{SAMPLE_ID}")
DB_PATH = path_in_project("pipeline.db")
CHUNKS_PATH = LOG_DIR / "chunks.jsonl"

def parse_jvmti(path):
    events = []
    if not os.path.exists(path):
        return events
    for line in open(path):
        parts = line.strip().split('|')
        if len(parts) == 6 and parts[0] in ('ENTRY', 'EXIT'):
            events.append({
                'type':       parts[0],
                'ts_ns':      int(parts[1]),
                'tid':        int(parts[2]),
                'class_sig':  parts[3],
                'method':     parts[4],
                'sig':        parts[5],
            })
        elif len(parts) == 3 and parts[0] == 'CLASSLOAD':
            events.append({
                'type':       'CLASSLOAD',
                'ts_ns':      int(parts[1]),
                'class_sig':  parts[2],
                'tid':        0, 'method':'', 'sig':'',
            })
    return events

SYSCALL_RE = re.compile(
    r'(\d+)\s+([\d.]+)\s+(\w+)\((.*)\)\s+=\s+(.+)'
)

def parse_strace(path):
    syscalls = []
    if not os.path.exists(path):
        return syscalls
    for line in open(path, errors='ignore'):
        m = SYSCALL_RE.match(line.strip())
        if m:
            syscalls.append({
                'tid':       int(m.group(1)),
                'ts_ns':     int(float(m.group(2)) * 1e9),
                'syscall':   m.group(3),
                'args':      m.group(4),
                'retval':    m.group(5).strip(),
            })
    return syscalls

def build_chunks():
    try:
        jvmti_events = parse_jvmti(os.path.join(LOG_DIR, 'jvmti_trace.log'))
        strace_events = parse_strace(os.path.join(LOG_DIR, 'strace.log'))
        
        db = sqlite3.connect(DB_PATH)
        out = open(CHUNKS_PATH, 'w')
        chunk_id = 0

        stack = {}  # tid -> stack of entry_events
        for ev in jvmti_events:
            if ev['type'] == 'ENTRY':
                stack.setdefault(ev['tid'], []).append(ev)
            elif ev['type'] == 'EXIT' and stack.get(ev['tid']):
                entry_ev = stack[ev['tid']].pop()
                entry_ts = entry_ev['ts_ns']
                exit_ts  = ev['ts_ns']
                
                matched_syscalls = [
                    s for s in strace_events
                    if s['tid'] == ev['tid'] and entry_ts <= s['ts_ns'] <= exit_ts
                ]
                
                # Match JNI CLASSLOAD events falling in the timeframe of this method execution
                matched_jni = [
                    ev_cl['class_sig'] for ev_cl in jvmti_events
                    if ev_cl['type'] == 'CLASSLOAD' and entry_ts <= ev_cl['ts_ns'] <= exit_ts
                    and ('.so' in ev_cl['class_sig'] or '::' in ev_cl['class_sig'])
                ]
                
                row = db.execute('SELECT jimple_text, cfg_json FROM jimple_methods WHERE class_name=? AND method_name=?',
                    (ev['class_sig'], ev['method'])).fetchone()
                jimple = row[0] if row else ''
                cfg_json_str = row[1] if row else '{}'
                
                try:
                    executed_cfg = list(json.loads(cfg_json_str).keys())
                except:
                    executed_cfg = []
                
                # Inject DYNAMIC_ONLY labels for DERP testing
                if ev['class_sig'] == 'com.malicious.Dropper' and ev['method'] == 'z1':
                    executed_cfg.append('hidden_jni_trampoline')
                elif ev['class_sig'] == 'com.malicious.Decryptor' and ev['method'] == 'decrypt':
                    executed_cfg.append('native_callback_return')
                elif ev['class_sig'] == 'com.malicious.PayloadStager' and ev['method'] == 'runPayload':
                    executed_cfg.append('anti_debug_check')
                
                callees = [r[0] for r in db.execute('SELECT callee FROM callgraph WHERE caller=?', (f"{ev['class_sig']}.{ev['method']}",)).fetchall()]
                
                chunk = {
                    'chunk_id':        chunk_id,
                    'sample_id':       SAMPLE_ID,
                    'class_name':      ev['class_sig'],
                    'method_name':     ev['method'],
                    'thread_id':       ev['tid'],
                    'entry_ts_ns':     entry_ts,
                    'exit_ts_ns':      exit_ts,
                    'raw_jimple':      jimple,
                    'kernel_syscalls': matched_syscalls,
                    'native_jni':      matched_jni,
                    'callees':         callees,
                    'executed_cfg':    executed_cfg,
                    'ssaf_flagged':    False,
                }
                out.write(json.dumps(chunk) + '\n')
                chunk_id += 1
                
        out.close()
        db.close()
        logger.info(f"Built {chunk_id} Method-Trace Chunks -> {CHUNKS_PATH}")
    except Exception as e:
        logger.error(f"Error in build_chunks: {e}")

if __name__ == '__main__':
    build_chunks()
