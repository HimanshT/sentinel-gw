# Sentinel Gateway

Sentinel Gateway is a FastAPI and React API gateway demo with Redis-backed
settings, metrics, traffic-log streams, threats, rate limiting, and reverse
proxying to a configured upstream service.

## Run With Docker Compose

```bash
docker compose up --build
```

Services:

- Frontend: http://localhost:5173
- Backend: http://localhost:8000
- Redis: localhost:6379

Inside Docker, the frontend container reaches the backend at
`http://backend:8000`. From your browser or terminal on the host machine, use
`http://localhost:8000`.

Optional Gemini configuration:

```bash
GEMINI_API_KEY="your-key" docker compose up --build
```

## Reverse Proxy Basics

The gateway listens on `http://localhost:8000`. The `backendUrl` setting is the
upstream application protected by the gateway, not the gateway itself.

Example:

```text
client -> http://localhost:8000/get -> gateway checks -> https://httpbin.org/get
```

Fresh installs default `backendUrl` to `https://httpbin.org` so proxying can be
tested immediately.

Test the gateway health route:

```bash
curl http://localhost:8000/gateway/health
```

Test allowed reverse proxy traffic:

```bash
curl "http://localhost:8000/get?hello=world"
```

Test deterministic blocking before the upstream is called:

```bash
curl -i "http://localhost:8000/get?id=1%20or%201=1"
```

Expected result:

```text
HTTP/1.1 403 Forbidden
```

Redis keys used by the gateway:

- `sentinel:gateway:settings`
- `sentinel:gateway:metrics`
- `sentinel:gateway:traffic_logs`
- `sentinel:gateway:threats`
- `sentinel:gateway:rate_limit:<client-ip>`

Inspect Redis:

```bash
redis-cli HGETALL sentinel:gateway:metrics
redis-cli GET sentinel:gateway:settings
redis-cli XREVRANGE sentinel:gateway:traffic_logs + - COUNT 10
redis-cli LRANGE sentinel:gateway:threats 0 -1
redis-cli KEYS 'sentinel:gateway:rate_limit:*'
```
