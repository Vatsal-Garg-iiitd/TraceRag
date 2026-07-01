from qdrant_client import QdrantClient
from loguru import logger

from config import QDRANT_COLLECTION, path_in_project

COLLECTION_NAME = QDRANT_COLLECTION
DB_PATH = path_in_project("qdrant_storage")

def verify():
    logger.info("Connecting to local Qdrant...")
    client = QdrantClient(path=str(DB_PATH))
    
    count = client.count(collection_name=COLLECTION_NAME)
    logger.info(f"Total points in collection '{COLLECTION_NAME}': {count.count}")
    
    points = client.scroll(
        collection_name=COLLECTION_NAME,
        limit=10,
        with_payload=True,
        with_vectors=True
    )[0]
    
    for p in points:
        payload = p.payload
        is_sens = payload.get('ssaf_flagged')
        logger.info(f"Point {p.id}:")
        logger.info(f"  Method: {payload.get('class_name')}.{payload.get('method_name')}")
        logger.info(f"  Sensitive? {is_sens}")
        logger.info(f"  Syscalls: {len(payload.get('kernel_syscalls', []))}")
        logger.info(f"  Vector shape: {len(p.vector)}")
        logger.info("-" * 40)

if __name__ == "__main__":
    verify()
