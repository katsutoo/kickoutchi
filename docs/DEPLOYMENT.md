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
- `LOG_LEVEL`
- `WEB_BASE_URL`
- `HOST`
- `PORT`
- `HTTP_READ_HEADER_TIMEOUT`
- `HTTP_READ_TIMEOUT`
- `HTTP_WRITE_TIMEOUT`
- `HTTP_IDLE_TIMEOUT`
- `HTTP_READY_TIMEOUT`
- `HTTP_SHUTDOWN_TIMEOUT`
- `DB_MAX_CONNS`
- `DB_MIN_CONNS`
- `DB_MAX_CONN_LIFETIME`
- `DB_MAX_CONN_IDLE_TIME`
- `DB_HEALTH_CHECK_PERIOD`
- `DB_CONNECT_TIMEOUT`
- `SESSION_COOKIE_NAME`
- `SESSION_TTL`
- `SESSION_REFRESH_WINDOW`
- `COOKIE_DOMAIN`
- `COOKIE_SECURE`
- `COOKIE_SAME_SITE`
- `PASSWORD_RESET_TOKEN_TTL`
- `EMAIL_VERIFICATION_TOKEN_TTL`
- `OAUTH_STATE_TTL`
- `CSRF_ALLOWED_ORIGINS`
- `TRUSTED_PROXY_CIDRS`
- `ARGON2_MEMORY`
- `ARGON2_TIME`
- `ARGON2_THREADS`
- `ARGON2_KEY_LENGTH`
- `ARGON2_SALT_LENGTH`
- `AUTH_IP_RATE_LIMIT_REQUESTS`
- `AUTH_IP_RATE_LIMIT_WINDOW`
- `AUTH_IP_RATE_LIMIT_BURST`
- `AUTH_ACCOUNT_RATE_LIMIT_REQUESTS`
- `AUTH_ACCOUNT_RATE_LIMIT_WINDOW`
- `AUTH_ACCOUNT_RATE_LIMIT_BURST`
- `AUTH_RESEND_VERIFICATION_RATE_LIMIT_REQUESTS`
- `AUTH_RESEND_VERIFICATION_RATE_LIMIT_WINDOW`
- `AUTH_RESEND_VERIFICATION_RATE_LIMIT_BURST`
- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_REDIRECT_URL`
- `R2_ACCOUNT_ID`
- `R2_BUCKET`
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_REGION`
- `R2_SIGNED_UPLOAD_TTL`
- `R2_SIGNED_READ_TTL`
- `POLAR_WEBHOOK_SECRET`
- `RESEND_API_KEY`
- `RESEND_FROM_EMAIL`
- `RESEND_API_BASE_URL`

### Web

- `PUBLIC_APP_URL`
- `PUBLIC_API_URL`

Recommended defaults:
- `COOKIE_SECURE=true` in production
- `AUTH_RESEND_VERIFICATION_RATE_LIMIT_REQUESTS=1`
- `AUTH_RESEND_VERIFICATION_RATE_LIMIT_WINDOW=1m`
- `AUTH_RESEND_VERIFICATION_RATE_LIMIT_BURST=1`

---

## Edge and network security

- Keep Cloudflare proxy enabled for public API/Web traffic
- Enforce HTTPS and HSTS in production
- Restrict `CSRF_ALLOWED_ORIGINS` to known app domains only
- Set `TRUSTED_PROXY_CIDRS` so forwarded client IP headers are only trusted from known proxies

---

## Email domain security (Resend)

- Configure SPF record for sender domain
- Configure DKIM keys provided by Resend
- Set DMARC policy (`p=quarantine` or stronger when stable)
- Validate DNS setup before enabling billing reminder emails
- In `APP_ENV=production`, Resend config is required and the API will fail to start without it

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
  - repeated auth email delivery failures
