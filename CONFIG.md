# Backend Configuration Guide

This doc covers essential environment variables and how to configure CORS for the PocketBridge backend deployed to Railway.

## CORS
- `CORS_ORIGIN`: Comma-separated list of allowed origins.
  - Example (Vercel): `https://pocketbridge-dun.vercel.app`
  - Multiple: `https://pocketbridge-dun.vercel.app, http://localhost:3000`
- `CORS_CREDENTIALS`: Set to `true` only if you need cookies/auth headers.
  - If `true`, do not use `*` in `CORS_ORIGIN`.
 - Important: Do NOT include trailing slashes in origins.

The backend is configured to:
- Respond to preflight requests globally (`OPTIONS *`).
- Include common headers like `X-User-ID`.
- Return a clean response without throwing for disallowed origins.

### Verify CORS
Preflight (OPTIONS):
```
curl -i -X OPTIONS "https://<railway-domain>/api/devices" \
  -H "Origin: https://pocketbridge-dun.vercel.app" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: X-User-ID, Content-Type"
```

Actual request:
```
curl -i "https://<railway-domain>/api/devices" \
  -H "Origin: https://pocketbridge-dun.vercel.app" \
  -H "X-User-ID: <your_public_key_hex>"
```

## Environment Summary
See `.env.example` for full list. Key variables:
- `DATABASE_URL` or individual `POSTGRES_*` vars
- `REDIS_URL` or individual `REDIS_*` vars
- `SERVER_PUBLIC_KEY_HEX`, `SERVER_PRIVATE_KEY_HEX` (server identity)
- `WS_SESSION_TIMEOUT`, `WS_REPLAY_WINDOW_DAYS`
- `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX_REQUESTS`

## Deployment Notes (Railway)
- Set `CORS_ORIGIN` to your frontend domain to avoid browser blocks.
- Restart the service after changing envs.
- For WebSocket: client should connect to `wss://<railway-domain>/ws`.

### Troubleshooting
- Symptom: Browser shows 404 on preflight with "Access-Control-Allow-Origin missing".
  - Cause: Origin mismatch due to trailing slash or incorrect domain.
  - Fix: Ensure `CORS_ORIGIN` is set exactly to your domain without trailing slash (e.g., `https://pocketbridge-dun.vercel.app`) and redeploy/restart.
