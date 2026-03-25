import logging
import os
import httpx
from typing import Optional

from . import config_manager

logger = logging.getLogger(__name__)


def _build_proxy_config() -> dict:
    """
    Build an httpx proxy map from environment variables.

    LLM_HTTP_PROXY / LLM_HTTPS_PROXY / LLM_NO_PROXY take precedence over the
    standard HTTP_PROXY / HTTPS_PROXY / NO_PROXY vars.
    """
    http_proxy  = os.getenv("LLM_HTTP_PROXY")  or os.getenv("HTTP_PROXY")  or os.getenv("http_proxy")
    https_proxy = os.getenv("LLM_HTTPS_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")
    no_proxy    = os.getenv("LLM_NO_PROXY")    or os.getenv("NO_PROXY")    or os.getenv("no_proxy")

    proxies: dict = {}
    if http_proxy:
        proxies["http://"] = http_proxy
    if https_proxy:
        proxies["https://"] = https_proxy
    if no_proxy:
        for host in (h.strip() for h in no_proxy.split(",") if h.strip()):
            proxies[f"all://{host}"] = None

    if proxies:
        logger.info("LLMAgent: outbound proxy configured: %s", {k: v for k, v in proxies.items() if v})

    return proxies


class LLMAgent:
    """
    Secure LLM agent wrapper.

    Reads provider settings from config_manager on every request so that
    changes made via PATCH /config/llm take effect immediately without restart.

    When LLM_API_URL is not configured (or cleared at runtime) the agent
    falls back to mock mode — safe canned responses for testing.
    """

    def __init__(self):
        self._proxies = _build_proxy_config()
        cfg = config_manager.get_llm()
        mode = "mock" if not cfg.get("api_url", "").strip() else "live"
        logger.info(
            "LLMAgent initialised — mode=%s model=%s proxy=%s",
            mode, cfg.get("model"), "yes" if self._proxies else "no",
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def mock_mode(self) -> bool:
        return config_manager.is_mock_mode()

    @property
    def model(self) -> str:
        return config_manager.get_llm().get("model", "")

    async def query(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        user_context: dict = None,
    ) -> str:
        if self.mock_mode:
            return self._mock_response(prompt)
        return await self._real_query(prompt, system_prompt)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _mock_response(self, prompt: str) -> str:
        return (
            "[MOCK LLM RESPONSE] I processed your query safely. "
            f"Query length: {len(prompt)} chars. "
            "Set LLM_API_URL (or use the Config page as administrator) to enable a real backend."
        )

    async def _real_query(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Call an OpenAI-compatible chat completions endpoint using current runtime config."""
        cfg = config_manager.get_llm()

        headers = {
            "Authorization": f"Bearer {cfg['api_key']}",
            "Content-Type": "application/json",
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model":      cfg["model"],
            "messages":   messages,
            "max_tokens": cfg["max_tokens"],
        }

        timeout = float(cfg.get("timeout_seconds", 30))
        async with httpx.AsyncClient(timeout=timeout, proxies=self._proxies or None) as client:
            response = await client.post(cfg["api_url"], headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
