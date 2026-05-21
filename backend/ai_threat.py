import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional


AI_CACHE_FILE = Path(__file__).resolve().parents[1] / "logs" / "ai_threat_cache.json"
AI_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    project_root = Path(__file__).resolve().parents[1]
    load_dotenv(project_root / ".env")
    load_dotenv(project_root / "backend" / ".env")
    load_dotenv(project_root / "frontent" / ".env")


def analyze_unknown_threat(entry: dict) -> dict:
    cached_analysis = _get_cached_analysis(entry)
    if cached_analysis:
        return cached_analysis

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {
            "aiScore": 0,
            "aiCategory": "AI Disabled",
            "aiReason": "GEMINI_API_KEY is not configured",
            "aiCached": False,
        }

    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    prompt = _build_prompt(entry)
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
        "generationConfig": {
            "temperature": 0,
            "responseMimeType": "application/json",
        },
    }

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={api_key}"
    )
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            response_body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "aiScore": 0,
            "aiCategory": "AI Error",
            "aiReason": str(exc),
            "aiCached": False,
        }

    analysis = _parse_gemini_response(response_body)
    _save_cached_analysis(entry, analysis)
    return analysis


def _build_prompt(entry: dict) -> str:
    request_context = {
        "method": entry.get("method"),
        "path": entry.get("path"),
        "query": entry.get("query") or {},
        "body": entry.get("body") or "",
        "ip": entry.get("ip"),
    }

    return (
        "You are an API gateway threat classifier. Analyze the HTTP request "
        "for unknown security threats such as SQL injection variants, XSS, "
        "command injection, SSRF, path traversal, credential leakage, abnormal "
        "probing, or suspicious automation. Return strict JSON only with: "
        "score as a number from 0 to 1, category as a short label, and reason "
        "as one short sentence. Request:\n"
        f"{json.dumps(request_context, ensure_ascii=True)}"
    )


def _parse_gemini_response(response_body: dict) -> dict:
    candidates = response_body.get("candidates") or []
    first_candidate = candidates[0] if candidates else {}
    parts = first_candidate.get("content", {}).get("parts") or []
    text = parts[0].get("text", "{}") if parts else "{}"

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        try:
            parsed = json.loads(match.group(0)) if match else {}
        except json.JSONDecodeError:
            parsed = {}

    score = parsed.get("score", 0)
    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0

    score = max(0, min(score, 1))
    category = str(parsed.get("category") or "Unknown").strip()[:80]
    reason = str(parsed.get("reason") or "Gemini completed analysis").strip()[:240]

    return {
        "aiScore": score,
        "aiCategory": category,
        "aiReason": reason,
        "aiCached": False,
    }


def _cache_key(entry: dict) -> str:
    cache_basis = {
        "method": entry.get("method"),
        "path": entry.get("path"),
        "query": entry.get("query") or {},
        "body": entry.get("body") or "",
    }
    serialized = json.dumps(cache_basis, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _load_cache() -> dict:
    if not AI_CACHE_FILE.exists() or AI_CACHE_FILE.stat().st_size == 0:
        return {}

    try:
        cache = json.loads(AI_CACHE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}

    return cache if isinstance(cache, dict) else {}


def _write_cache(cache: dict) -> None:
    AI_CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def _get_cached_analysis(entry: dict) -> Optional[dict]:
    analysis = _load_cache().get(_cache_key(entry))
    if not isinstance(analysis, dict):
        return None

    cached = dict(analysis)
    cached["aiCached"] = True
    return cached


def _save_cached_analysis(entry: dict, analysis: dict) -> None:
    if analysis.get("aiCategory") in {"AI Disabled", "AI Error"}:
        return

    cache = _load_cache()
    cached = dict(analysis)
    cached["aiCached"] = True
    cache[_cache_key(entry)] = cached
    _write_cache(cache)
