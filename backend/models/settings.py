from pydantic import BaseModel,AnyHttpUrl
from pathlib import Path
import json

class GatewaySettings(BaseModel):
    backend_url:AnyHttpUrl="http://localhost:8000"
    rate_limit_per_minute:int = 120
    ai_threat_detection:bool=False
    blocked_ips:list[str]=[]
    whitelisted_ips:list[str]=[]


