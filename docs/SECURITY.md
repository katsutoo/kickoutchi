# Security

Security is a release gate for every phase, not a final hardening task.

---

## Security principles

1. Secure by default
2. Least privilege for users, services, and operators
3. Defense in depth across API, WebSocket, storage, and billing
4. Auditable high-risk actions
5. Explicit failure handling and incident readiness

---

## Threat model (initial)

- Account takeover (credential stuffing, password reuse)
- WebSocket abuse (flooding, spoofed events, unauthorized joins)
- Broken authorization (kick/ban/marriage/admin actions)
- Abuse and harassment in social systems
- File upload abuse (malicious content, oversized files)
- Webhook forgery (Polar)
- Data leaks through logs, backups, or misconfigured storage

---

## Authentication and sessions

- Password hashing: Argon2id with configurable parameters in env
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Lax` (or stricter if compatible)
- Session rotation on login, password reset, and sensitive account changes
- Invalidate all sessions on password reset
- Rate limits on login, register, and forgot-password endpoints
- Email verification required before social/real-time features
- CSRF protection on state-changing cookie-auth routes (origin checks and/or CSRF token)

---

## OAuth policy

- OAuth providers: GitHub, Google, X
- Store only provider identity by default (`provider`, `provider_uid`, `provider_email`)
- Do not store provider access/refresh tokens at launch unless a feature requires provider API access
- If token storage is added later, encrypt at rest and rotate encryption keys

---

## Gorilla WebSocket security

- Upgrade handshake requires a valid authenticated session
- Strict `Origin` allowlist (no wildcard origins in production)
- Enforce TLS in production
- Validate every incoming message against schema and size limits
- Per-IP, per-user, and per-connection rate limits
- Heartbeat with ping/pong and idle disconnect
- Authorization checks on every privileged action (kick, ban, apartment moderation)
- Backpressure protections: bounded outbound queues and slow-consumer disconnect

Network boundary rule:
- Trust forwarded client IP headers only from configured trusted proxy CIDRs

---

## Authorization model

- Service-layer authorization is mandatory for all state-changing actions
- Apartment owner permissions are enforced server-side only
- Marriage, family, and subscription actions must verify actor ownership
- Admin/moderation actions require role checks and audit logging

---

## Upload and storage security (Cloudflare R2)

- Use short-lived signed upload URLs
- Validate MIME type and magic bytes server-side
- Enforce max size and image dimension limits
- Reject SVG unless sanitized pipeline exists
- Keep buckets private; serve through signed read URLs or controlled proxy

---

## Billing and webhook security

- Verify Polar webhook signature before processing
- Idempotent processing by `provider_event_id`
- Ignore and log unknown event types
- Store minimal billing data required for entitlements and support
- Subscription reminders:
  - 7-day: in-app only
  - 2-day: in-app + Resend email

---

## Email security (Resend)

- Configure SPF, DKIM, and DMARC for sender domain
- Use dedicated sender identity (`RESEND_FROM_EMAIL`)
- Keep reminder and auth templates versioned
- Track message IDs in delivery records for support/debugging

---

## Data protection

- Encrypt transport with HTTPS only
- Use encrypted backups and verify restore regularly
- Minimize PII in logs; never log plaintext passwords or tokens
- Maintain retention policy for logs, notifications, and audit entries

---

## Monitoring and response

- Alert on:
  - spikes in 401/403/429
  - repeated webhook signature failures
  - WebSocket abnormal disconnect spikes
  - unusual login/reset patterns
- Incident readiness:
  - secret rotation runbook
  - account/session invalidation playbook
  - communication template for user-facing incidents

---

## Secure release checklist

- [ ] `go test ./...` and `go test -race ./...` pass
- [ ] `go vet`, `staticcheck`, and `govulncheck` pass
- [ ] Cookie flags verified in production config
- [ ] CSRF protections verified for state-changing cookie-auth routes
- [ ] WebSocket origin allowlist configured
- [ ] WebSocket message-size and rate-limit protections configured
- [ ] Polar webhook signature verification enabled
- [ ] R2 upload validation (type, magic bytes, size) verified
- [ ] Resend DNS auth (SPF/DKIM/DMARC) validated
- [ ] Backup restore test completed in staging
