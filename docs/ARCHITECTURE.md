# Architecture

This architecture is simple, production-friendly, and aligned with the Go and Svelte guidance you shared.

---

## Engineering principles

1. Start as a modular monolith (fastest to ship, easiest to debug)
2. Keep Go layers explicit: Handler -> Service -> Repository -> Database
3. Keep SvelteKit server-first and progressively enhanced
4. Add infrastructure only when a phase requires it
5. Use PostgreSQL as the single source of truth

---

## Tech stack

### Backend (Go)

| Category | Tool | Why |
|---|---|---|
| Language | Go 1.24+ | Simple concurrency + strong performance |
| Router | Chi | Small, stdlib-friendly, clean middleware |
| DB access | pgx + sqlc | SQL-first and type-safe generated queries |
| Migrations | Goose | SQL migration workflow |
| Logging | slog | Structured logs and good ops defaults |
| Validation | go-playground/validator | Request DTO validation |
| Password hashing | Argon2id | Secure password storage |
| IDs | UUIDv7 | Sortable, globally unique IDs |
| Real-time | Gorilla WebSocket | Apartments, presence, DM events |
| Email | Resend | Transactional and reminder emails |
| Testing | testcontainers-go | Real Postgres integration tests |

### Frontend (SvelteKit)

| Category | Tool | Why |
|---|---|---|
| Framework | SvelteKit (Svelte 5) | Server-first and fast UI iteration |
| Language | TypeScript (strict) | Safer refactors and API contracts |
| Data fetch | `+page.server.ts` + form actions | Progressive enhancement baseline |
| Client HTTP | ky | Retries, timeouts, clean API wrapper |
| Forms | Superforms + Zod | Type-safe validation end-to-end |
| Caching | TanStack Query (selective) | Only where client cache adds value |
| UI | Tailwind + Bits UI + lucide-svelte | Fast, accessible component base |
| Testing | Bun test + Playwright | Unit + E2E coverage |

### Infrastructure

| Category | Tool |
|---|---|
| Hosting | Railway (API + Web + Postgres) |
| CDN / DNS / WAF | Cloudflare |
| Object storage | Cloudflare R2 (avatars/assets) |
| Payments | Polar.sh |
| CI | GitHub Actions |

---

## High-level system

```text
Browser (SvelteKit)
    |
    | HTTPS (REST + WebSocket)
    v
Go API (Chi)
    |
    +--> PostgreSQL (auth, game state, social, chat metadata)
    |
    +--> Cloudflare R2 (profile images, user assets)
    |
    +--> Resend (email delivery for account + billing reminders)
    |
    +--> Polar webhooks (subscription entitlements)
```

---

## Backend structure (Go)

```text
apps/api/
  cmd/
    server/main.go

  internal/
    config/
      config.go
      env.go

    router/
      router.go
      v1.go

    handler/
      auth_handler.go
      pet_handler.go
      apartment_handler.go
      friend_handler.go
      dm_handler.go
      relationship_handler.go
      notification_handler.go
      subscription_handler.go
      health_handler.go

    service/
      auth_service.go
      pet_service.go
      apartment_service.go
      friend_service.go
      dm_service.go
      relationship_service.go
      notification_service.go
      subscription_service.go
      transaction.go

    repository/
      user_repository.go
      pet_repository.go
      apartment_repository.go
      friend_repository.go
      dm_repository.go
      relationship_repository.go
      notification_repository.go
      subscription_repository.go

    realtime/
      hub.go
      apartment_actor.go
      presence.go
      dm_dispatcher.go
      notification_dispatcher.go

    worker/
      subscription_reminder_worker.go

    middleware/
      auth.go
      logging.go
      ratelimit.go
      security.go

    database/sqlc/   # generated, never edited manually

    apierror/
      errors.go

    validator/
      validator.go

    client/
      r2_client.go
      polar_client.go
      resend_client.go

  sql/
    sqlc.yaml
    schema/
      YYYYMMDDHHMMSS_*.sql
    queries/
      *.sql
```

### Request flow

```text
HTTP / WS request
  -> handler (parse and response mapping)
  -> service (business rules and transactions)
  -> repository (sqlc query wrappers)
  -> PostgreSQL
```

### Real-time model

- One `Hub` tracks active user connections.
- One `ApartmentActor` goroutine per active apartment session.
- Actor state includes visitors, bans, and occupancy caps.
- All in-app notifications are pushed over Gorilla WebSocket when users are online.
- WebSocket upgrades require authenticated sessions and strict origin allowlist checks.
- Incoming events are schema-validated with message size and rate limits.
- Rules enforced server-side:
  - Apartment max visitors: `6`
  - House max visitors: `12`
  - Owner/moderator can kick/ban in their space

### Notification architecture

- Domain events are emitted by services (`friendship_accepted`, `marriage_confirmed`, `subscription_expiry_7d`, `subscription_expiry_2d`).
- `NotificationService` writes notifications to PostgreSQL first (source of truth).
- `NotificationDispatcher` pushes unread notifications through Gorilla WebSocket for online users.
- If user is offline, notifications remain unread and appear on next app open.
- User preferences can mute social notifications, but billing reminders remain mandatory.
- `SubscriptionReminderWorker` runs daily and schedules reminders with idempotency keys:
  - 7 days before expiry at 09:00 UTC: in-app notification only
  - 2 days before expiry at 09:00 UTC: in-app notification + Resend email

---

## Frontend structure (SvelteKit)

```text
apps/web/
  src/
    features/
      auth/
        components/
        api/
        schemas/
        stores/
      pets/
        components/
        api/
        schemas/
      apartments/
        components/
        api/
      social/
        components/
        api/
      relationships/
        components/
        api/
      cosmetics/
        components/
        api/

    routes/
      (public)/
        login/+page.server.ts
        login/+page.svelte
        register/+page.server.ts
        register/+page.svelte
      (app)/
        +layout.server.ts
        +layout.svelte
        +page.svelte
        pet/+page.server.ts
        pet/+page.svelte
        apartment/+page.server.ts
        apartment/+page.svelte
        friends/+page.server.ts
        friends/+page.svelte
        messages/+page.server.ts
        messages/+page.svelte
        family/+page.server.ts
        family/+page.svelte
        shop/+page.server.ts
        shop/+page.svelte

    lib/
      api/client.ts
      query/client.ts
      query/keys.ts
      config/env.ts
      server/auth.ts

    shared/
      components/
      actions/
      utils/
      types/
```

### Frontend standards

- Use Svelte 5 runes (`$state`, `$derived`, `$effect`) correctly.
- Keep business logic in server load/actions and backend services, not in UI components.
- Prefer form actions and progressive enhancement before adding client-only complexity.
- Use TanStack Query only for data that benefits from client caching or optimistic updates.

---

## Security and reliability baseline

- Argon2id password hashing with tunable parameters
- OAuth providers: GitHub, Google, X
- OAuth provider tokens are not stored at launch unless a later feature requires them
- Email verification + password reset tokens
- httpOnly secure sessions
- CSRF protections for state-changing cookie-auth routes
- Rate limits on auth and messaging endpoints
- Gorilla WebSocket origin allowlist, message size limits, and flood protection
- Structured audit logs for kicks, bans, and moderation actions
- Health endpoints: `/health/live` and `/health/ready`
- Graceful shutdown for HTTP server and WebSocket actors

---

## Scale path (only when needed)

Keep Phase 1-2 simple:

- Single Go API deployment
- Single PostgreSQL
- In-memory presence for one instance

Upgrade later if concurrency requires it:

- Add Redis/Dragonfly for distributed presence/session coordination
- Add queue for async notifications
- Split services only after clear performance bottlenecks
