# WebSocket Protocol

This protocol defines real-time messaging over Gorilla WebSocket.

---

## Connection

- Endpoint: `GET /v1/ws/connect`
- Auth: existing session cookie (httpOnly) validated during upgrade
- Required checks during upgrade:
  - session is valid and not expired
  - request origin is in allowlist
  - user is not globally banned/suspended

Optional query params:
- `last_event_id` for replaying missed notification/DM events

---

## Envelope

All messages use one JSON envelope.

```json
{
  "id": "0195f7f6-9f62-7c1d-b2d8-9b6fd9a0b6b7",
  "type": "client.dm.send",
  "ts": "2026-02-19T13:20:00Z",
  "ref": "optional-client-correlation-id",
  "data": {}
}
```

Fields:
- `id`: UUIDv7 message id
- `type`: event type string
- `ts`: RFC3339 UTC timestamp
- `ref`: optional correlation id for request/response pairing
- `data`: event payload

---

## Client -> Server events

- `client.apartment.join`
- `client.apartment.leave`
- `client.apartment.kick`
- `client.apartment.ban`
- `client.dm.send`
- `client.notification.mark_read`
- `client.heartbeat`

### Example: send DM

```json
{
  "id": "0195f7f6-9f62-7c1d-b2d8-9b6fd9a0b6b8",
  "type": "client.dm.send",
  "ts": "2026-02-19T13:20:01Z",
  "data": {
    "recipient_id": "0195f7f6-9f62-7a2f-a6c4-56ec4467dfaa",
    "content": "yo, want to visit my apartment?"
  }
}
```

---

## Server -> Client events

- `server.system.ready`
- `server.system.ack`
- `server.system.error`
- `server.apartment.state`
- `server.apartment.user_joined`
- `server.apartment.user_left`
- `server.apartment.user_kicked`
- `server.apartment.user_banned`
- `server.dm.received`
- `server.notification.new`
- `server.notification.unread_count`

### Example: notification push

```json
{
  "id": "0195f7f6-9f62-7d79-b97f-6f52de4f9db4",
  "type": "server.notification.new",
  "ts": "2026-02-19T13:20:03Z",
  "data": {
    "notification_id": "0195f7f6-9f62-70e3-b3f8-31c1dcb14552",
    "kind": "wedding",
    "title": "Wedding bells",
    "body": "Aki and Ren just got married!",
    "payload": {
      "partner_a_id": "0195f7f6-9f62-79db-91f6-4d1f2e70ad11",
      "partner_b_id": "0195f7f6-9f62-7f35-b8b2-c03d86bbbe76"
    }
  }
}
```

---

## Limits and safeguards

- Max incoming message size: `16KB`
- Max outgoing queue per connection: bounded (default: 256 messages)
- DM content max length: `500` chars
- Rate limits (starting point):
  - inbound messages: `20/s`, burst `40`
  - DM sends: `5/s`, burst `10`
  - apartment moderation actions: `2/s`, burst `5`

Slow consumer policy:
- if outbound queue is full, server disconnects with error code `WS_SLOW_CONSUMER`

---

## Error model

Errors are sent via `server.system.error`.

```json
{
  "id": "0195f7f6-9f62-71ee-9ec9-0f5d7ea1e183",
  "type": "server.system.error",
  "ts": "2026-02-19T13:20:04Z",
  "ref": "optional-client-correlation-id",
  "data": {
    "code": "WS_FORBIDDEN",
    "message": "You are not allowed to perform this action"
  }
}
```

Common codes:
- `WS_UNAUTHORIZED`
- `WS_FORBIDDEN`
- `WS_RATE_LIMITED`
- `WS_INVALID_PAYLOAD`
- `WS_APARTMENT_FULL`
- `WS_BANNED_FROM_APARTMENT`
- `WS_SLOW_CONSUMER`

---

## Reconnect strategy (client)

- Exponential backoff: `1s`, `2s`, `5s`, `10s`, max `30s`
- Reconnect with `last_event_id` so server can replay missed DMs/notifications
- On reconnect success, client refreshes apartment and notification unread state

---

## Versioning

- Protocol version is path-based with API version (`/v1/ws/connect`)
- Breaking changes require `/v2/ws/connect`
