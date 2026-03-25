"""
Runtime configuration manager.

Loads initial values from environment variables and exposes thread-safe
get / update helpers.  Settings updated via PATCH /config take effect
immediately without a restart.
"""
import copy
import logging
import os
import threading

logger = logging.getLogger(__name__)

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Provider presets — returned to the UI so it can auto-fill fields
# ---------------------------------------------------------------------------
PROVIDER_PRESETS = {
    "openai": {
        "api_url": "https://api.openai.com/v1/chat/completions",
        "model":   "gpt-4o",
    },
    "groq": {
        "api_url": "https://api.groq.com/openai/v1/chat/completions",
        "model":   "llama3-8b-8192",
    },
    "ollama": {
        "api_url": "http://ollama:11434/v1/chat/completions",
        "model":   "llama3.2",
    },
    "anthropic-proxy": {
        "api_url": "http://litellm:4000/v1/chat/completions",
        "model":   "claude-sonnet-4-6",
    },
    "custom": {
        "api_url": "",
        "model":   "",
    },
}

# ---------------------------------------------------------------------------
# Internal state — initialised from env vars, mutable at runtime
# ---------------------------------------------------------------------------
_config: dict = {
    "llm": {
        "provider":        os.getenv("LLM_PROVIDER", "custom"),
        "api_url":         os.getenv("LLM_API_URL", ""),
        "api_key":         os.getenv("LLM_API_KEY", ""),
        "model":           os.getenv("LLM_MODEL", "gpt-4o"),
        "max_tokens":      int(os.getenv("LLM_MAX_TOKENS", "2048")),
        "timeout_seconds": int(os.getenv("LLM_TIMEOUT", "30")),
    },
    "policy": {
        "max_input_length":        int(os.getenv("MAX_INPUT_LENGTH", "32768")),
        "pii_filter_input":        True,
        "pii_filter_output":       True,
        "block_prompt_injection":  True,
        "block_secret_exfiltration": True,
    },
    "server": {
        "allowed_origins": os.getenv("ALLOWED_ORIGINS", "http://localhost:3000"),
        "trusted_proxies": os.getenv("TRUSTED_PROXIES", ""),
    },
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def get() -> dict:
    """Return a deep copy of the full configuration (including api_key)."""
    with _lock:
        return copy.deepcopy(_config)


def safe_view() -> dict:
    """Return full config with the LLM api_key masked — safe to send to UI."""
    with _lock:
        view = copy.deepcopy(_config)
        _mask_key(view)
        return view


def update_section(section: str, updates: dict) -> dict:
    """
    Merge *updates* into *section* and return the new safe view.

    If ``updates`` contains ``api_key`` with the masked placeholder the
    existing key is preserved unchanged (user did not intend to replace it).
    """
    with _lock:
        if section not in _config:
            raise KeyError(f"Unknown config section: '{section}'")

        if section == "llm" and "api_key" in updates:
            raw = updates["api_key"]
            # Ignore the masked sentinel value sent back by the UI
            if "****" in raw or raw == "":
                updates = {k: v for k, v in updates.items() if k != "api_key"}

        _config[section].update(updates)
        logger.info("Config updated — section=%s fields=%s", section, list(updates.keys()))
        view = copy.deepcopy(_config)
        _mask_key(view)
        return view


def get_llm() -> dict:
    """Return a copy of the LLM section (with real api_key) for internal use."""
    with _lock:
        return copy.deepcopy(_config["llm"])


def get_policy() -> dict:
    with _lock:
        return copy.deepcopy(_config["policy"])


def is_mock_mode() -> bool:
    with _lock:
        return not bool(_config["llm"].get("api_url", "").strip())


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _mask_key(cfg: dict) -> None:
    key = cfg["llm"].get("api_key", "")
    if key:
        cfg["llm"]["api_key"] = key[:4] + "****" + key[-2:] if len(key) > 6 else "****"
