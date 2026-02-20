# Deployment

Infrastructure targets your requested stack: Railway + Cloudflare + R2 + Polar.

---

## Phase 1 deployment shape

```text
Cloudflare (DNS, proxy, TLS, WAF)
    |
Railway
  - kickoutchi-api (Go)
  - kickoutchi-web (SvelteKit)
  - PostgreSQL
```

---

## Phase 6 additions

```text
Cloudflare R2 (media assets)
Polar.sh (subscription checkout + webhooks)
Resend (subscription reminder and auth emails)
```

---

## Railway services

### API service

- Runtime: Go binary in container
- Health checks:
  - `GET /health/live`
  - `GET /health/ready`
- Internal access to Postgres via Railway private network

### Web service

- Runtime: SvelteKit production adapter
- Serves UI and communicates with API

### PostgreSQL

- Managed Railway Postgres
- Migrations executed by API release pipeline

---

## Environment variables

### API

- `DATABASE_URL`
- `APP_ENV`
- `SESSION_SECRET`
- `COOKIE_DOMAIN`
- `COOKIE_SECURE`
- `ARGON2_MEMORY`
- `ARGON2_TIME`
- `ARGON2_THREADS`
- `ALLOWED_ORIGINS`
- `CSRF_TRUSTED_ORIGINS`
- `WS_ALLOWED_ORIGINS`
- `WS_MAX_MESSAGE_BYTES`
- `TRUSTED_PROXY_CIDRS`
- `OAUTH_GITHUB_ID`
- `OAUTH_GITHUB_SECRET`
- `OAUTH_GOOGLE_ID`
- `OAUTH_GOOGLE_SECRET`
- `OAUTH_X_ID`
- `OAUTH_X_SECRET`
- `R2_ENDPOINT`
- `R2_BUCKET`
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `POLAR_WEBHOOK_SECRET`
- `RESEND_API_KEY`
- `RESEND_FROM_EMAIL`

### Web

- `PUBLIC_APP_URL`
- `PUBLIC_API_URL`

Recommended defaults:
- `WS_MAX_MESSAGE_BYTES=16384`
- `COOKIE_SECURE=true` in production

---

## Edge and network security

- Keep Cloudflare proxy enabled for public API/Web traffic
- Enforce HTTPS and HSTS in production
- Restrict CORS and WebSocket origins to known app domains only
- Trust real client IP headers only from trusted proxy network

---

## Email domain security (Resend)

- Configure SPF record for sender domain
- Configure DKIM keys provided by Resend
- Set DMARC policy (`p=quarantine` or stronger when stable)
- Validate DNS setup before enabling billing reminder emails

---

## CI/CD baseline

- Pull request:
  - Go tests (`go test ./...`, `go test -race ./...`)
  - Go checks (`go vet`, `staticcheck`, `govulncheck`)
  - Svelte checks (`svelte-check`, unit tests, build)
- Merge to main:
  - Build and deploy API + Web on Railway

---

## Operational baseline

- Daily database backups
- Restore drill in staging at least monthly
- Structured JSON logs from API (`slog`)
- Error tracking for API and web
- Alert on:
  - readiness failures
  - sustained 5xx spikes
  - websocket connection instability
