# Project Phases

Each phase is intentionally small and shippable. Do not build Phase N+1 infrastructure inside Phase N.

---

## Phase 1 - Foundation, Auth, and Profile

**Goal:** users can create accounts, log in, and manage basic profile data.

**Backend**
- [ ] Bootstrap Go API with Chi, pgx, sqlc, Goose, slog
- [ ] Email/password auth with Argon2id
- [ ] OAuth login: GitHub, Google, X
- [ ] Resend integration for transactional auth email flows
- [ ] Session management (httpOnly secure cookies)
- [ ] User profile CRUD (display name, avatar metadata)

**Frontend**
- [ ] SvelteKit app shell with route groups `(public)` and `(app)`
- [ ] Login/register/forgot password forms with Superforms + Zod
- [ ] Basic authenticated home screen

**Infra**
- [ ] Railway services: API, Web, Postgres
- [ ] Cloudflare DNS and proxy
- [ ] CI baseline: lint, typecheck, tests, build

**Security gates**
- [ ] Session cookies set with `HttpOnly`, `Secure`, `SameSite`
- [ ] Session rotation on login and password reset
- [ ] Auth endpoints protected by per-IP and per-account rate limits
- [ ] CSRF controls enabled for state-changing cookie-auth routes
- [ ] Request validation enforced on all auth/profile handlers
- [ ] No plaintext secrets in repo or logs

**Validation checkpoints**
- [ ] Register, verify email, login, logout all work
- [ ] OAuth login works for at least one provider end-to-end
- [ ] Protected routes reject unauthenticated access

---

## Phase 2 - Pet Creation and Evolution Core

**Goal:** users can create a pet and start a basic growth path.

**Backend**
- [ ] Pet entity and progression state (baby -> teen -> adult)
- [ ] Evolution tracks (start with 2-3 original tracks only)
- [ ] Basic care loop rules (hunger, energy, happiness)

**Frontend**
- [ ] Pet creation flow with track selection
- [ ] Pet status panel and interaction actions
- [ ] Evolution timeline UI

**Security gates**
- [ ] Pet mutations require authenticated ownership checks
- [ ] Progression and stat updates validated server-side only
- [ ] IDOR tests for pet endpoints (cannot mutate another user's pet)

**Validation checkpoints**
- [ ] New user can create one pet successfully
- [ ] Pet state updates persist after refresh/relogin
- [ ] Evolution trigger works for at least one full path

---

## Phase 3 - Friends and Friend-Only Messaging

**Goal:** players can add friends and chat privately in real-time.

**Backend**
- [ ] Friend request, accept, decline, unfriend
- [ ] DM rules: message allowed only if friendship is accepted
- [ ] Gorilla WebSocket channel for online DM and notification delivery
- [ ] Offline message persistence in PostgreSQL
- [ ] Notification event on friendship success (notify both users)

**Frontend**
- [ ] Friend list and friend request inbox
- [ ] Tiny in-game phone UI for DMs
- [ ] Presence indicators (online/offline)
- [ ] In-app notification inbox/toast surface

**Security gates**
- [ ] Gorilla WebSocket handshake requires valid session and allowed origin
- [ ] WS message schema validation, max payload size, and per-user rate limits
- [ ] Friend-only DM rule enforced server-side on every message path
- [ ] Notification writes are idempotent by event key

**Validation checkpoints**
- [ ] Non-friends cannot DM each other
- [ ] Friends can exchange real-time messages
- [ ] Offline user receives missed messages after login
- [ ] Friendship acceptance triggers in-app notification to both users

---

## Phase 4 - Apartment Visits and Presence

**Goal:** players can visit each other homes with occupancy and moderation rules.

**Backend**
- [ ] Apartment session model and visit join/leave
- [ ] Owner controls: kick and ban visitors
- [ ] Occupancy rules enforced server-side
- [ ] Real-time presence events via Gorilla WebSocket

**Frontend**
- [ ] Apartment view with visitor list
- [ ] Join/leave apartment interactions
- [ ] Owner controls panel (kick/ban)

**Security gates**
- [ ] Kick/ban actions require owner authorization checks in service layer
- [ ] Occupancy caps enforced server-side (never client-trusted)
- [ ] Apartment moderation actions written to audit logs

**Rule checkpoints**
- [ ] Apartment visitor limit is exactly `6`
- [ ] Join attempt over `6` returns user-friendly warning

**Validation checkpoints**
- [ ] Multiple users can enter the same apartment in real-time
- [ ] Owner can kick a user and user is removed instantly
- [ ] Banned users cannot re-enter until unbanned

---

## Phase 5 - Marriage, Family, and House Upgrade

**Goal:** relationship gameplay unlocks family and bigger housing.

**Backend**
- [ ] Mutual-consent marriage flow
- [ ] Family unit model (partners + kids)
- [ ] House unlock only for married players
- [ ] House capacity rule and child creation flow
- [ ] Wedding notification fan-out to both partners and their accepted friends

**Frontend**
- [ ] Relationship UI (proposal, accept/decline)
- [ ] Family panel and kids overview
- [ ] House view with garden theme

**Security gates**
- [ ] Marriage transition requires explicit mutual consent and anti-replay checks
- [ ] Family and house actions verify partner/family ownership on backend
- [ ] Wedding fan-out applies dedupe and block-list filtering before notify

**Rule checkpoints**
- [ ] Same-sex marriage is fully supported
- [ ] Families can have kids regardless of partner combination
- [ ] House visitor limit is exactly `12`

**Validation checkpoints**
- [ ] Unmarried users cannot unlock house
- [ ] Married users can unlock and host in house
- [ ] House blocks new entry when 12 visitors are present
- [ ] Wedding event notifies both partners and all unique friends of both users

---

## Phase 6 - Cosmetics and Subscription

**Goal:** launch fair monetization with cosmetic-only premium benefits.

**Backend**
- [ ] Cosmetic catalog and inventory ownership
- [ ] Polar.sh subscription webhook handling
- [ ] Entitlement checks for premium cosmetic access
- [ ] R2 upload for profile images and user assets
- [ ] Subscription reminder worker for expiry notifications
- [ ] 7-day reminder at 09:00 UTC: in-app notification only
- [ ] 2-day reminder at 09:00 UTC: in-app notification + Resend email

**Frontend**
- [ ] Cosmetic shop and inventory UI
- [ ] Subscription settings page
- [ ] Locked premium item experience with upgrade prompts

**Security gates**
- [ ] Polar webhook signature verification and idempotent event handling
- [ ] R2 uploads use short-lived signed URLs with MIME + magic-byte checks
- [ ] Reminder worker uses UTC date normalization and one-send idempotency keys
- [ ] Resend sender domain verified with SPF, DKIM, and DMARC

**Monetization checkpoints**
- [ ] Premium plan price set to `EUR 5.99`
- [ ] No pay-to-win stat modifiers in premium path

**Validation checkpoints**
- [ ] Subscription activate/cancel updates entitlements correctly
- [ ] Premium users can use premium cosmetics
- [ ] Free users keep access to all gameplay systems
- [ ] User with expiry in 7 days receives in-app reminder only
- [ ] User with expiry in 2 days receives in-app reminder and email reminder

---

## Phase 7 - Moderation, Safety, and Policies

**Goal:** make social systems safe enough for public launch.

**Backend**
- [ ] Report, block, mute flows
- [ ] Audit logs for moderation actions
- [ ] Rate limits for auth, DM, and social endpoints
- [ ] Abuse monitoring and alerting

**Frontend**
- [ ] In-app report/block controls
- [ ] Policy pages (privacy, terms, community rules)
- [ ] Account data export and deletion request views

**Security gates**
- [ ] Moderation endpoints require role-based authorization checks
- [ ] Report and block abuse endpoints have anti-spam rate limits
- [ ] Moderation audit logs are append-only and queryable for investigations

**Validation checkpoints**
- [ ] Blocked users cannot DM or visit blocked user spaces
- [ ] Moderation actions are traceable in audit logs
- [ ] Policy and account controls are accessible in-app

---

## Phase 8 - Launch Hardening and Operations

**Goal:** production readiness for scale and reliability.

**Backend and infra**
- [ ] Load test real-time apartment occupancy and DM throughput
- [ ] Backups and restore runbook validated
- [ ] SLO dashboards (latency, errors, websocket stability)
- [ ] Graceful shutdown and deployment rollback verified

**Frontend**
- [ ] Performance budget checks (LCP, JS bundle size)
- [ ] Mobile browser QA pass
- [ ] Error states and reconnect UX polish

**Security gates**
- [ ] Backup restore drill is tested and documented
- [ ] Secret rotation drill completed for core credentials
- [ ] Threat model and abuse scenarios reviewed against production telemetry
- [ ] Pre-launch security checklist from `SECURITY.md` is fully green

**Validation checkpoints**
- [ ] Can recover from backup in staging
- [ ] Core user journey works under expected peak load
- [ ] On-call checklist and incident process documented

---

## Optional Phase 9 - Mobile Companion (Flutter)

Browser remains primary. Mobile app should reuse existing API contracts and ship as companion scope first (chat, profile, pet status), then expand later.
