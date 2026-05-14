from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Match
import json
from pathlib import Path
from datetime import datetime, timedelta
from uuid import uuid4
from backend.models.settings import GatewaySettings


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class GatewayMetrics:
    def __init__(self):
        self.total_requests = 0
        self.allowed_traffic = 0
        self.blocked_threats = 0


metrics = GatewayMetrics()

valid_paths = {
    "/" : ["GET"],
    "/stats" : ["GET"],
    "/test/{path:path}" : ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
}


malicious_signatures = ["or 1=1", "--", "<script>", "union select", "drop table", "exec("]


# Loggin Entries
LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "traffic_logs.json"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


# Load and save the settings
CONFIG_PATH = Path(__file__).resolve().parent / "config" / "gw_settings.conf"

def load_settings() -> GatewaySettings:
    if CONFIG_PATH.exists() and CONFIG_PATH.stat().st_size > 0:
        return GatewaySettings.parse_raw(CONFIG_PATH.read_text(encoding="utf-8"))
    return GatewaySettings()

def save_settings(settings: GatewaySettings):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(settings.model_dump_json(indent=2, by_alias=True), encoding="utf-8")

# load the settings
settings = load_settings()
rate_counters : dict[str,tuple[datetime,int]]={}

def append_traffic_log(entry: dict):
    LOG_FILE.touch(exist_ok=True)

    if LOG_FILE.stat().st_size == 0:
        data = []
    else:
        with LOG_FILE.open("r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []

    data.append(entry)

    # Keep the file bounded to the most recent 100 entries.
    if len(data) > 100:
        data = data[-100:]

    with LOG_FILE.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)



def load_traffic_logs(limit: int = 100):
    if not LOG_FILE.exists() or LOG_FILE.stat().st_size == 0:
        return []

    try:
        data = json.loads(LOG_FILE.read_text(encoding="utf-8") or "[]")
        if isinstance(data, list):
            entries = list(reversed(data[-limit:]))
            normalized = []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                normalized.append({
                    "id": entry.get("id") or entry.get("timestamp") or uuid4().hex,
                    "timestamp": entry.get("timestamp"),
                    "ip": entry.get("ip") or entry.get("ip address") or "unknown",
                    "method": entry.get("method"),
                    "path": entry.get("path"),
                    "status": entry.get("status"),
                    "reason": entry.get("reason") or entry.get("Reason") or "N/A",
                    "aiScore": entry.get("aiScore") if entry.get("aiScore") is not None else 0,
                    "aiCategory": entry.get("aiCategory") or entry.get("AI analysis") or "Clean",
                })
            return normalized
    except json.JSONDecodeError:
        pass
    return []


@app.get("/api/logs")
def api_logs():
    return load_traffic_logs(100)


@app.get("/api/stats")
def api_stats():
    return {
        "total": metrics.total_requests,
        "blocked": metrics.blocked_threats,
        "allowed": metrics.allowed_traffic,
    }


@app.get("/api/config")
def api_get_config():
    return settings.model_dump(by_alias=True)


@app.post("/api/config")
def api_update_config(new_settings: GatewaySettings):
    global settings
    settings = new_settings
    save_settings(settings)
    return settings.model_dump(by_alias=True)


@app.middleware("http")
async def gateway_middleware(request:Request,call_next):
    # Do not count frontend admin/API polling or settings endpoints as gateway traffic.
    internal_prefixes = ("/api", "/stats", "/gateway")
    if request.url.path.startswith(internal_prefixes):
        return await call_next(request)

    metrics.total_requests += 1

    # Check if any router route matches the incoming request
    body = await request.body()
    body_text = body.decode("utf-8","ignore")

    route_exists = any(
        route.matches(request.scope)[0]==Match.FULL
        for route in app.router.routes
    )

    client_ip = request.client.host
    log_entry = {
        "id": uuid4().hex,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "method": request.method,
        "path": request.url.path,
        "query": dict(request.query_params),
        "body": body_text,
        "route_exists": route_exists,
        "malicious": False,
        "ip": client_ip,
        "aiScore": 0,
        "aiCategory": "Clean",
        "reason": "Passed Security Checks",
        "status":"allowed"
    }
    
    if not route_exists:
        metrics.blocked_threats +=1
        log_entry["blocked"] = True
        log_entry["reason"] = "route_not_found"
        append_traffic_log(log_entry)
        return JSONResponse({"detail": "Route not found"}, status_code=404)
    
    now = datetime.utcnow()

    if client_ip in settings.blocked_ips:
        metrics.blocked_threats += 1
        log_entry["blocked"] = True
        log_entry["reason"] = "Blocked IP"
        append_traffic_log(log_entry)
        return JSONResponse({"detail": "Blocked IP"}, status_code=403)
    
    if settings.whitelisted_ips and client_ip not in settings.whitelisted_ips:
        metrics.blocked_threats += 1
        log_entry["blocked"] = True
        log_entry["reason"] = "Non whitelisted IP"
        append_traffic_log(log_entry)
        return JSONResponse({"detail": "IP not whitelisted"}, status_code=403)
    

    # handle rate limiting
    window_start,count = rate_counters.get(client_ip,(now,0))
    if now-window_start >= timedelta(minutes=1):
        window_start,count = now,0
    count +=1
    rate_counters[client_ip] = (window_start,count)

    if count > settings.rate_limit_per_minute:
        metrics.blocked_threats += 1
        return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)

    if any(sig in request.url.query.lower() or sig in body_text.lower() for sig in malicious_signatures):
        metrics.blocked_threats +=1
        log_entry["blocked"] = True
        log_entry["reason"] = "malicious_payload"
        append_traffic_log(log_entry)
        return JSONResponse({"detail": "Blocked: malicious payload detected"}, status_code=403)

    
    metrics.allowed_traffic += 1
    log_entry["blocked"] = False
    append_traffic_log(log_entry)
    return await call_next(request)


@app.get("/")
async def root():
    return {"message": "Gateway is alive"}

@app.get("/stats")
async def get_stats():
    return {
        "total_requests": metrics.total_requests,
        "allowed_traffic": metrics.allowed_traffic,
        "blocked_threats": metrics.blocked_threats,
    }

@app.api_route("/test/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def test_route(path: str, request: Request):
    return {
        "status": "ok",
        "path": path,
        "method": request.method,
        "query": dict(request.query_params),
        "body": (await request.body()).decode("utf-8", "ignore"),
    }


# settings AI
@app.get("/gateway/settings")
async def get_gateway_settings():
    return settings.dict()

@app.post("/gateway/settings")
async def update_gateway_settings(new_settings:GatewaySettings):
    global settings
    settings = new_settings
    save_settings(settings)
    return {"status":"ok"}

