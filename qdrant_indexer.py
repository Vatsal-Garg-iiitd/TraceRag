import json
import uuid
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance, PointStruct
from loguru import logger

from config import QDRANT_COLLECTION, path_in_project

import sys

if len(sys.argv) < 2:
    print("Usage: python qdrant_indexer.py <sample_id>")
    sys.exit(1)

SAMPLE_ID = int(sys.argv[1])
LOG_DIR = path_in_project(f"logs/sample_{SAMPLE_ID}")

SENSITIVE_PATH = LOG_DIR / "summarized_chunks.jsonl"
BENIGN_PATH = LOG_DIR / "chunks_benign.jsonl"
COLLECTION_NAME = QDRANT_COLLECTION
QDRANT_PATH = path_in_project("qdrant_storage")

def load_chunks(path):
    if not path.exists():
        return []
    with open(path, 'r') as f:
        return [json.loads(line) for line in f]

def index_chunks():
    try:
        sensitive_chunks = load_chunks(SENSITIVE_PATH)
        benign_chunks = load_chunks(BENIGN_PATH)
        
        all_chunks = sensitive_chunks + benign_chunks
        if not all_chunks:
            logger.info("No chunks to index.")
            return

        logger.info("Loading embedding model (all-MiniLM-L6-v2)...")
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        logger.info("Connecting to local Qdrant database (in-memory/file)...")
        try:
            client = QdrantClient(path=str(QDRANT_PATH))
            collections = client.get_collections().collections
        except Exception as e:
            logger.error(f"Failed to initialize local Qdrant. Error: {e}")
            return

        # Create collection if not exists
        if not any(c.name == COLLECTION_NAME for c in collections):
            client.create_collection(
                collection_name=COLLECTION_NAME,
                vectors_config=VectorParams(size=384, distance=Distance.COSINE),
            )
            logger.info(f"Created collection '{COLLECTION_NAME}'.")
            
        points = []
        for chunk in all_chunks:
            is_sensitive = chunk.get('ssaf_flagged', False)
            
            # Decide text to embed
            if is_sensitive:
                text_to_embed = chunk.get('llm_summary', '')
                if not text_to_embed:
                    text_to_embed = chunk.get('raw_jimple', '')
            else:
                text_to_embed = chunk.get('raw_jimple', '')
                
            vector = model.encode(text_to_embed).tolist()
            
            point_id = str(uuid.uuid4())
            
            # Build Qdrant payload exactly as specified in architecture
            payload = {
                "summary": chunk.get('llm_summary', "Raw Jimple Stub (Benign)"),
                "raw_jimple": chunk.get('raw_jimple', ""),
                "kernel_syscalls": chunk.get('kernel_syscalls', []),
                "native_jni": chunk.get('native_jni', []),
                "class_name": chunk.get('class_name', ""),
                "method_name": chunk.get('method_name', ""),
                "callees": chunk.get('callees', []),
                "executed_cfg": chunk.get('executed_cfg', []),
                "thread_id": chunk.get('thread_id', 0),
                "entry_ts_ns": chunk.get('entry_ts_ns', 0),
                "exit_ts_ns": chunk.get('exit_ts_ns', 0),
                "ssaf_flagged": is_sensitive,
                "sample_id": chunk.get('sample_id', SAMPLE_ID)
            }
            
            points.append(PointStruct(id=point_id, vector=vector, payload=payload))
            
        logger.info(f"Upserting {len(points)} points to Qdrant...")
        client.upsert(
            collection_name=COLLECTION_NAME,
            points=points
        )
        logger.info("Indexing complete.")
    except Exception as e:
        logger.error(f"Error in index_chunks: {e}")

if __name__ == '__main__':
    index_chunks()
