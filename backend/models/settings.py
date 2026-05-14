from pydantic import BaseModel, AnyHttpUrl, Field
from pathlib import Path
import json

class GatewaySettings(BaseModel):
    backend_url: AnyHttpUrl = Field("http://localhost:8000", alias="backendUrl")
    rate_limit_per_minute: int = Field(120, alias="rateLimit")
    ai_threat_detection: bool = Field(False, alias="aiEnabled")
    ai_threshold: float = Field(0.7, alias="aiThreshold")
    blocked_ips: list[str] = Field(default_factory=list, alias="blockedIps")
    whitelisted_ips: list[str] = Field(default_factory=list, alias="whitelistIps")

    model_config = {"populate_by_name": True}


