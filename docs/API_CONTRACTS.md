# API Contracts

This document defines the initial HTTP API surface by phase.

---

## Conventions

- Base path: `/v1`
- Content type: `application/json`
- Auth: secure session cookie (httpOnly)

Response envelopes:

Success:

```json
{
  "data": {}
}
```

Error:

```json
{
  "error": "human readable message",
  "code": "MACHINE_CODE",
  "details": {}
}
```

---

## Health

- `GET /health/live`
- `GET /health/ready`

---

## Phase 1 endpoints (Auth + Profile)

- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `POST /v1/auth/logout`
- `POST /v1/auth/forgot-password`
- `POST /v1/auth/reset-password`
- `POST /v1/auth/verify-email`
- `POST /v1/auth/resend-verification`
- `GET /v1/auth/oauth/:provider/start`
- `GET /v1/auth/oauth/:provider/callback`
- `GET /v1/me`
- `PATCH /v1/me`
- `POST /v1/me/avatar/upload-url`
- `POST /v1/me/avatar/confirm`
- `DELETE /v1/me/avatar`

---

## Phase 2 endpoints (Pets)

- `POST /v1/pets`
- `GET /v1/pets/me`
- `PATCH /v1/pets/me/care`
- `GET /v1/pets/me/events`

---

## Phase 3 endpoints (Friends + DM + Notifications)

- `POST /v1/friends/requests`
- `POST /v1/friends/requests/:request_id/accept`
- `POST /v1/friends/requests/:request_id/decline`
- `DELETE /v1/friends/:friend_user_id`
- `GET /v1/friends`

- `GET /v1/dm/threads`
- `GET /v1/dm/threads/:user_id/messages`
- `POST /v1/dm/threads/:user_id/messages` (HTTP fallback when WS unavailable)

- `GET /v1/notifications`
- `POST /v1/notifications/:notification_id/read`
- `POST /v1/notifications/read-all`
- `GET /v1/notification-preferences` (social notification settings)
- `PATCH /v1/notification-preferences` (social notification settings)

`notification-preferences` payload scope:
- `social_enabled`
- `friendship_enabled`
- `wedding_enabled`

Billing reminders are mandatory policy and not configurable via this endpoint.

---

## Phase 4 endpoints (Apartments)

- `GET /v1/apartments/me`
- `PATCH /v1/apartments/me`
- `POST /v1/apartments/:owner_user_id/visit`
- `POST /v1/apartments/:owner_user_id/leave`
- `POST /v1/apartments/:owner_user_id/kick`
- `POST /v1/apartments/:owner_user_id/ban`
- `DELETE /v1/apartments/:owner_user_id/ban/:user_id`

WebSocket:
- `GET /v1/ws/connect`

---

## Phase 5 endpoints (Marriage + Family + House)

- `POST /v1/relationships/proposals`
- `POST /v1/relationships/proposals/:proposal_id/accept`
- `POST /v1/relationships/proposals/:proposal_id/decline`
- `GET /v1/relationships/me`

- `POST /v1/family/kids`
- `GET /v1/family`

- `POST /v1/houses/unlock`
- `GET /v1/houses/me`
- `PATCH /v1/houses/me`

---

## Phase 6 endpoints (Cosmetics + Subscription)

- `GET /v1/shop/items`
- `POST /v1/shop/purchase`
- `GET /v1/inventory`
- `POST /v1/inventory/equip`

- `POST /v1/subscriptions/checkout`
- `GET /v1/subscriptions/me`
- `POST /v1/subscriptions/cancel`

- `POST /v1/uploads/avatar/presign`
- `POST /v1/uploads/asset/presign`

Webhooks:
- `POST /v1/webhooks/polar`

---

## Phase 7 endpoints (Safety + Moderation)

- `POST /v1/blocks/:user_id`
- `DELETE /v1/blocks/:user_id`
- `GET /v1/blocks`

- `POST /v1/reports`
- `GET /v1/reports/me`

Admin/moderator routes:
- `GET /v1/admin/reports`
- `POST /v1/admin/reports/:report_id/resolve`
- `POST /v1/admin/users/:user_id/mute`
- `POST /v1/admin/users/:user_id/ban`

---

## Webhook contract rules

- Signature validation required before parsing payload
- Idempotent processing by provider event ID
- Return 2xx only after successful persistence
- Return 4xx on invalid signature

---

## Versioning and compatibility

- Backward-compatible additions stay in `/v1`
- Breaking changes move to `/v2`
- Deprecated endpoints should return sunset metadata before removal
