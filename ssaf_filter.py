import json
import re
from loguru import logger

from config import path_in_project

import sys

if len(sys.argv) < 2:
    print("Usage: python ssaf_filter.py <sample_id>")
    sys.exit(1)

SAMPLE_ID = int(sys.argv[1])
LOG_DIR = path_in_project(f"logs/sample_{SAMPLE_ID}")

CHUNKS_PATH = LOG_DIR / "chunks.jsonl"
SENSITIVE_PATH = LOG_DIR / "chunks_sensitive.jsonl"
BENIGN_PATH = LOG_DIR / "chunks_benign.jsonl"

SSAF_PATTERNS = [
    r'DexClassLoader', r'PathClassLoader', r'loadClass', r'defineClass',
    r'javax\.crypto', r'AES', r'RSA', r'KeyGenerator', r'SecretKeySpec', r'Cipher',
    r'SmsManager', r'sendTextMessage', r'TelephonyManager', r'subscriberId',
    r'Runtime\.exec', r'ProcessBuilder', r'execve',
    r'java\.lang\.reflect', r'getDeclaredMethod', r'invoke\(',
    r'HttpURLConnection', r'OkHttpClient', r'Socket\(', r'DatagramSocket',
    r'BOOT_COMPLETED', r'AlarmManager', r'JobScheduler',
    r'su\b', r'SELinux', r'AccessibilityService', r'DeviceAdminReceiver',
    r'System\.loadLibrary', r'System\.load\(',
    r'openat.*', r'connect.*', r'mmap.*' 
]

compiled_patterns = [re.compile(p, re.IGNORECASE) for p in SSAF_PATTERNS]

def filter_chunks():
    try:
        sensitive_out = open(SENSITIVE_PATH, 'w')
        benign_out = open(BENIGN_PATH, 'w')
        
        sensitive_count = 0
        benign_count = 0
        
        if not os.path.exists(CHUNKS_PATH):
            logger.error("chunks.jsonl not found!")
            return


        for line in open(CHUNKS_PATH):
            chunk = json.loads(line)
            text_to_search = chunk['raw_jimple'] + str(chunk['kernel_syscalls']) + str(chunk['native_jni'])
            
            is_sensitive = any(p.search(text_to_search) for p in compiled_patterns)
            
            if is_sensitive:
                chunk['ssaf_flagged'] = True
                sensitive_out.write(json.dumps(chunk) + '\n')
                sensitive_count += 1
            else:
                chunk['ssaf_flagged'] = False
                benign_out.write(json.dumps(chunk) + '\n')
                benign_count += 1
                
        sensitive_out.close()
        benign_out.close()
        
        logger.info(f"SSAF Filtering complete. Sensitive: {sensitive_count}, Benign: {benign_count}")
    except Exception as e:
        logger.error(f"Error in filter_chunks: {e}")

if __name__ == '__main__':
    filter_chunks()
