# Notifications

Notification behavior is product-critical and must stay deterministic.

---

## Transport and channels

- In-app real-time delivery: Gorilla WebSocket
- In-app persistence: PostgreSQL notifications table
- Email delivery: Resend

If user is online, push through WebSocket and persist.
If user is offline, persist and show on next app open.

---

## Event matrix

| Event | Recipients | In-app | Email |
|---|---|---|---|
| Friendship accepted | Both users in the accepted friendship | Yes | No |
| Wedding confirmed | Both partners | Yes | No |
| Wedding broadcast | All accepted friends of partner A and partner B | Yes | No |
| Subscription expires in 7 days | Subscriber | Yes | No |
| Subscription expires in 2 days | Subscriber | Yes | Yes (Resend) |

---

## Wedding fan-out rules

- Build recipient set from accepted friends of both partners.
- Deduplicate recipients by user ID.
- Exclude blocked users according to current block rules.
- Add the two partners explicitly even if friend queries fail.

---

## Subscription reminder rules

- Daily worker checks active subscriptions.
- At `expiry_date - 7 days` at `09:00 UTC`: create in-app reminder.
- At `expiry_date - 2 days` at `09:00 UTC`: create in-app reminder and send Resend email.
- Use idempotency keys to avoid duplicate reminders.
- Store worker decisions in `subscription_reminder_state`.

Timezone policy:
- `current_period_end` is normalized to UTC date before reminder window checks.
- One reminder per user per window per subscription period.

Recommended idempotency key format:
- `sub:{subscription_id}:exp:{yyyy-mm-dd}:7d`
- `sub:{subscription_id}:exp:{yyyy-mm-dd}:2d`

---

## Delivery state model

- Notification states: `unread`, `read`
- Delivery states: `pending`, `sent`, `failed`
- Email delivery should store provider message ID from Resend when available

Retry policy:
- In-app delivery retries on reconnect automatically.
- Email delivery retries with bounded backoff (default: 3 attempts).

---

## UX requirements

- Show toast for newly received WebSocket notifications.
- Keep a notification inbox page for history and unread counts.
- Wedding notifications should include both partner display names.
- Subscription reminders should include expiry date and renewal link.

---

## Notification preferences

- Users can opt in/out of social notifications (friendship, wedding) in settings.
- Preference keys: `social_enabled`, `friendship_enabled`, `wedding_enabled`.
- Billing reminders remain mandatory:
  - 7-day in-app reminder cannot be disabled
  - 2-day in-app and email reminder cannot be disabled
