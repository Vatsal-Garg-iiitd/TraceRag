"""Load secrets and project settings from `.env` in the project root."""

import os
from pathlib import Path

_PROJECT_DIR = Path(__file__).resolve().parent


def _load_dotenv() -> None:
    env_file = _PROJECT_DIR / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


_load_dotenv()

PROJECT_ROOT = Path(
    os.environ.get("PROJECT_ROOT", str(_PROJECT_DIR))
).expanduser().resolve()


def path_in_project(*parts: str) -> Path:
    return PROJECT_ROOT.joinpath(*parts)


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable '{name}'. "
            "Copy .env.example to .env and set your credentials."
        )
    return value


def setup_langsmith_tracing() -> None:
    """Apply LangSmith / LangChain tracing env vars for @traceable decorators."""
    api_key = require_env("LANGCHAIN_API_KEY")
    tracing = os.environ.get("LANGCHAIN_TRACING_V2", "true")
    project = os.environ.get("LANGCHAIN_PROJECT", "Malware_detection")

    os.environ["LANGCHAIN_TRACING_V2"] = tracing
    os.environ["LANGCHAIN_PROJECT"] = project
    os.environ["LANGCHAIN_API_KEY"] = api_key
    os.environ.setdefault("LANGSMITH_API_KEY", api_key)
    os.environ.setdefault("LANGSMITH_TRACING", tracing)
    os.environ.setdefault("LANGSMITH_PROJECT", project)


def __getattr__(name: str):
    """Lazy-load secrets so path-only imports do not require API keys."""
    if name == "HF_API_KEY":
        return require_env("HF_API_KEY")
    if name == "HF_MODEL_ID":
        return os.environ.get("HF_MODEL_ID", "meta-llama/Meta-Llama-3-8B-Instruct")
    if name == "QDRANT_COLLECTION":
        return os.environ.get("QDRANT_COLLECTION", "hypertrace_rag")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
