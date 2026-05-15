import json
import os
from datetime import datetime
from uuid import uuid4

from backend.models.settings import GatewaySettings


class RedisStore:
    SETTINGS_KEY = "sentinel:gateway:settings"
    THREATS_KEY = "sentinel:gateway:threats"
    MAX_LOG_ENTRIES = 100

    def __init__(self):
        try:
            import redis
        except ImportError as exc:
            raise RuntimeError(
                "Redis support requires the 'redis' package. "
                "Install backend dependencies with: pip install -r backend/requirements.txt"
            ) from exc

        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.client = redis.Redis.from_url(redis_url, decode_responses=True)
        self.client.ping()

    def get_settings(self) -> GatewaySettings:
        raw_settings = self.client.get(self.SETTINGS_KEY)
        if not raw_settings:
            settings = GatewaySettings()
            self.save_settings(settings)
            return settings
        return GatewaySettings.model_validate_json(raw_settings)

    def save_settings(self, settings: GatewaySettings) -> GatewaySettings:
        self.client.set(self.SETTINGS_KEY, settings.model_dump_json(by_alias=True))
        return settings

    def delete_settings(self) -> GatewaySettings:
        self.client.delete(self.SETTINGS_KEY)
        settings = GatewaySettings()
        self.save_settings(settings)
        return settings

    def append_threat(self, entry: dict) -> None:
        normalized_entry = self._normalize_entry(entry)
        if normalized_entry["status"] != "blocked":
            return

        self.client.lpush(self.THREATS_KEY, json.dumps(normalized_entry))
        self.client.ltrim(self.THREATS_KEY, 0, self.MAX_LOG_ENTRIES - 1)

    def get_threats(self, limit: int = MAX_LOG_ENTRIES) -> list[dict]:
        return self._load_list(self.THREATS_KEY, limit)

    def delete_threat(self, threat_id: str) -> bool:
        threats = self.get_threats(self.MAX_LOG_ENTRIES)
        threat = next((item for item in threats if item.get("id") == threat_id), None)
        if not threat:
            return False

        return self.client.lrem(self.THREATS_KEY, 1, json.dumps(threat)) > 0

    def clear_threats(self) -> None:
        self.client.delete(self.THREATS_KEY)

    def _load_list(self, key: str, limit: int) -> list[dict]:
        entries = []
        for raw_entry in self.client.lrange(key, 0, max(limit - 1, 0)):
            try:
                decoded = json.loads(raw_entry)
            except json.JSONDecodeError:
                continue

            if isinstance(decoded, dict):
                entries.append(self._normalize_entry(decoded))

        return entries

    def _normalize_entry(self, entry: dict) -> dict:
        blocked = bool(entry.get("blocked", False))
        status = entry.get("status")
        if blocked:
            status = "blocked"
        elif status not in {"allowed", "blocked"}:
            status = "allowed"

        return {
            "id": entry.get("id") or uuid4().hex,
            "timestamp": entry.get("timestamp") or datetime.utcnow().isoformat() + "Z",
            "ip": entry.get("ip") or entry.get("ip address") or "unknown",
            "method": entry.get("method"),
            "path": entry.get("path"),
            "query": entry.get("query") or {},
            "body": entry.get("body") or "",
            "route_exists": entry.get("route_exists"),
            "malicious": bool(entry.get("malicious", False)),
            "blocked": status == "blocked",
            "status": status,
            "reason": entry.get("reason") or entry.get("Reason") or "N/A",
            "aiScore": entry.get("aiScore") if entry.get("aiScore") is not None else 0,
            "aiCategory": entry.get("aiCategory") or entry.get("AI analysis") or "Clean",
        }
