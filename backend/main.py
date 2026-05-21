from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, Response
from datetime import datetime
from uuid import uuid4
import httpx
from backend.ai_threat import analyze_unknown_threat
from backend.models.settings import GatewaySettings
from backend.store import RedisStore


app = FastAPI()
store = RedisStore()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


malicious_signatures = ["or 1=1", "--", "<script>", "union select", "drop table", "exec("]
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}
RESPONSE_HEADERS_TO_DROP = HOP_BY_HOP_HEADERS | {"content-length", "server", "date"}


def contains_malicious_signature(*values) -> bool:
    haystack_parts = []
    for value in values:
        if isinstance(value, dict):
            haystack_parts.extend(str(item) for pair in value.items() for item in pair)
        elif value is not None:
            haystack_parts.append(str(value))

    haystack = " ".join(haystack_parts).lower()
    return any(signature in haystack for signature in malicious_signatures)


def append_traffic_log(entry: dict):
    if entry.get("blocked"):
        entry["status"] = "blocked"
    elif entry.get("status") not in {"allowed", "blocked"}:
        entry["status"] = "allowed"

    store.append_traffic_log(entry)



def load_traffic_logs(limit: int = 100):
    return store.get_traffic_logs(limit)


def build_upstream_url(request: Request, settings: GatewaySettings) -> str:
    base_url = str(settings.backend_url).rstrip("/")
    path = request.url.path
    query = f"?{request.url.query}" if request.url.query else ""
    return f"{base_url}{path}{query}"


def proxy_request_headers(request: Request, upstream_host: str) -> dict:
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() != "host"
    }
    headers["host"] = upstream_host
    headers["x-forwarded-host"] = request.headers.get("host", "")
    headers["x-forwarded-proto"] = request.url.scheme
    headers["x-forwarded-for"] = request.client.host if request.client else ""
    return headers


def proxy_response_headers(headers) -> dict:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in RESPONSE_HEADERS_TO_DROP
    }


def points_to_gateway(upstream_url: str) -> bool:
    parsed_url = httpx.URL(upstream_url)
    host = parsed_url.host or ""
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    return host in {"localhost", "127.0.0.1", "0.0.0.0", "backend"} and port == 8000


@app.get("/api/logs")
def api_logs():
    return load_traffic_logs(100)


@app.get("/api/stats")
def api_stats():
    return store.get_metrics()


@app.get("/api/config")
def api_get_config():
    return store.get_settings().model_dump(by_alias=True, mode="json")


@app.post("/api/config")
def api_update_config(new_settings: GatewaySettings):
    return store.save_settings(new_settings).model_dump(by_alias=True, mode="json")


@app.delete("/api/config")
def api_delete_config():
    return store.delete_settings().model_dump(by_alias=True, mode="json")


@app.get("/api/threats")
def api_threats():
    return store.get_threats(100)


@app.delete("/api/threats")
def api_clear_threats():
    store.clear_threats()
    return {"status": "ok"}


@app.delete("/api/threats/{threat_id}")
def api_delete_threat(threat_id: str):
    if not store.delete_threat(threat_id):
        raise HTTPException(status_code=404, detail="Threat not found")
    return {"status": "ok"}


@app.get("/gateway/health")
async def gateway_health():
    return {"message": "Gateway is alive"}


@app.api_route("/gateway/echo/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def gateway_echo(path: str, request: Request):
    return {
        "status": "ok",
        "path": path,
        "method": request.method,
        "query": dict(request.query_params),
        "body": (await request.body()).decode("utf-8", "ignore"),
    }


@app.middleware("http")
async def gateway_middleware(request:Request,call_next):
    # Do not count frontend admin/API polling or settings endpoints as gateway traffic.
    internal_prefixes = ("/api", "/stats", "/gateway")
    if request.url.path.startswith(internal_prefixes):
        return await call_next(request)

    settings = store.get_settings()

    body = await request.body()
    body_text = body.decode("utf-8","ignore")

    client_ip = request.client.host
    log_entry = {
        "id": uuid4().hex,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "method": request.method,
        "path": request.url.path,
        "query": dict(request.query_params),
        "body": body_text,
        "upstreamUrl": build_upstream_url(request, settings),
        "malicious": False,
        "ip": client_ip,
        "aiScore": 0,
        "aiCategory": "Clean",
        "aiReason": "AI threat detection did not run",
        "aiCached": False,
        "reason": "Passed Security Checks",
        "status":"allowed"
    }

    if client_ip in settings.blocked_ips:
        store.increment_metrics(total=1, blocked=1)
        log_entry["blocked"] = True
        log_entry["aiScore"] = 1
        log_entry["aiCategory"] = "Blocked IP"
        log_entry["aiReason"] = "Client IP matched the configured blocked IP list"
        log_entry["reason"] = "Blocked IP"
        append_traffic_log(log_entry)
        return JSONResponse({"detail": "Blocked IP"}, status_code=403)
    
    if settings.whitelisted_ips and client_ip not in settings.whitelisted_ips:
        store.increment_metrics(total=1, blocked=1)
        log_entry["blocked"] = True
        log_entry["aiScore"] = 0.8
        log_entry["aiCategory"] = "Non Whitelisted IP"
        log_entry["aiReason"] = "Client IP was not present in the configured whitelist"
        log_entry["reason"] = "Non whitelisted IP"
        append_traffic_log(log_entry)
        return JSONResponse({"detail": "IP not whitelisted"}, status_code=403)
    

    count, retry_after = store.increment_rate_limit(client_ip)

    if count > settings.rate_limit_per_minute:
        store.increment_metrics(total=1, blocked=1)
        log_entry["blocked"] = True
        log_entry["status"] = "blocked"
        log_entry["aiScore"] = 0.7
        log_entry["aiCategory"] = "Rate Limit"
        log_entry["aiReason"] = "Client exceeded the configured request rate"
        log_entry["reason"] = "Rate limit exceeded"
        append_traffic_log(log_entry)
        return JSONResponse(
            {"detail": "Rate limit exceeded", "retryAfter": retry_after},
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    if contains_malicious_signature(request.url.query, dict(request.query_params), body_text):
        store.increment_metrics(total=1, blocked=1)
        log_entry["blocked"] = True
        log_entry["aiScore"] = 1
        log_entry["aiCategory"] = "Known Signature"
        log_entry["aiReason"] = "Request matched a configured malicious payload signature"
        log_entry["reason"] = "malicious_payload"
        append_traffic_log(log_entry)
        return JSONResponse({"detail": "Blocked: malicious payload detected"}, status_code=403)

    if settings.ai_threat_detection:
        ai_analysis = analyze_unknown_threat(log_entry)
        log_entry.update(ai_analysis)

        if log_entry["aiScore"] >= settings.ai_threshold:
            store.increment_metrics(total=1, blocked=1)
            log_entry["blocked"] = True
            log_entry["status"] = "blocked"
            log_entry["reason"] = log_entry.get("aiReason") or "AI threat threshold exceeded"
            append_traffic_log(log_entry)
            return JSONResponse({
                "detail": "Blocked: AI threat detected",
                "aiScore": log_entry["aiScore"],
                "aiCategory": log_entry["aiCategory"],
            }, status_code=403)

    
    store.increment_metrics(total=1, allowed=1)
    log_entry["blocked"] = False
    append_traffic_log(log_entry)
    return await call_next(request)


@app.get("/stats")
async def get_stats():
    metrics = store.get_metrics()
    return {
        "total_requests": metrics["total"],
        "allowed_traffic": metrics["allowed"],
        "blocked_threats": metrics["blocked"],
    }

@app.get("/gateway/settings")
async def get_gateway_settings():
    return store.get_settings().model_dump(by_alias=True, mode="json")

@app.post("/gateway/settings")
async def update_gateway_settings(new_settings:GatewaySettings):
    store.save_settings(new_settings)
    return {"status":"ok"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def reverse_proxy(path: str, request: Request):
    settings = store.get_settings()
    upstream_url = build_upstream_url(request, settings)

    if points_to_gateway(upstream_url):
        return JSONResponse(
            {
                "detail": "Reverse proxy target points back to this gateway. "
                "Set backendUrl to the upstream app you want to protect."
            },
            status_code=502,
        )

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=20) as client:
            upstream_response = await client.request(
                method=request.method,
                url=upstream_url,
                headers=proxy_request_headers(request, httpx.URL(upstream_url).host),
                content=await request.body(),
            )
    except httpx.RequestError as exc:
        return JSONResponse(
            {
                "detail": "Upstream request failed",
                "upstreamUrl": upstream_url,
                "error": str(exc),
            },
            status_code=502,
        )

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=proxy_response_headers(upstream_response.headers),
        media_type=upstream_response.headers.get("content-type"),
    )
