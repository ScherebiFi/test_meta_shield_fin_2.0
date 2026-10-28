from __future__ import annotations

import os
from typing import Any

import httpx


GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def cloud_available() -> bool:
    return bool(os.getenv("GROQ_API_KEY"))


async def ask_llama(system_prompt: str, user_prompt: str) -> str:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY n'est pas configurée.")
    model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.2,
            },
        )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
    return payload["choices"][0]["message"]["content"]