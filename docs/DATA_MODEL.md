# Data Model (PostgreSQL)

Use PostgreSQL for all persistent domains from day one (auth, gameplay, social, monetization). SQLite is only for local toy prototypes.

---

## Conventions

- Primary keys: UUIDv7
- Timestamps: `inserted_at`, `updated_at` (`timestamptz`)
- Soft delete where needed: `deleted_at`
- Enum-like fields can start as text + check constraints, then move to enum when stable

---

## Phase 1 tables (Auth + Accounts)

- `users`
  - `id`, `email`, `password_hash`, `display_name`, `role`, `email_verified_at`, `avatar_metadata`, `inserted_at`, `updated_at`
- `oauth_identities`
  - `id`, `user_id`, `provider`, `provider_uid`, `provider_email`
  - launch default: do not store provider access/refresh tokens
- `sessions`
  - `id`, `user_id`, `token_hash`, `expires_at`, `ip_address`, `user_agent`
- `email_tokens`
  - `id`, `user_id`, `token_hash`, `type`, `expires_at`, `used_at`

---

## Phase 2 tables (Pets)

- `pets`
  - `id`, `user_id`, `name`, `stage`, `track`, `mood`, `hunger`, `energy`, `hygiene`
- `pet_events`
  - `id`, `pet_id`, `event_type`, `payload_json`, `inserted_at`

---

## Phase 3 tables (Friends + DM)

- `friends`
  - `id`, `user_low_id`, `user_high_id`, `requested_by_user_id`, `status`, `inserted_at`, `updated_at`
  - canonical pair model avoids duplicate direction rows
  - status values: `pending`, `accepted`, `declined`
  - check constraint: `user_low_id < user_high_id`
  - unique constraint: `(user_low_id, user_high_id)`
- `direct_messages`
  - `id`, `sender_id`, `recipient_id`, `content`, `read_at`, `inserted_at`
- `blocks`
  - `id`, `blocker_id`, `blocked_id`, `inserted_at`
  - check constraint: `blocker_id <> blocked_id`
  - unique constraint: `(blocker_id, blocked_id)`

- `notifications`
  - `id`, `user_id`, `kind`, `title`, `body`, `payload_json`, `event_key`, `read_at`, `inserted_at`
  - `kind` starts with: `friendship_success`, `wedding`, `subscription_expiry_7d`, `subscription_expiry_2d`
  - unique constraint on `(user_id, event_key)` for idempotency

- `notification_deliveries`
  - `id`, `notification_id`, `channel`, `status`, `provider`, `provider_message_id`, `sent_at`, `failure_reason`, `inserted_at`, `updated_at`
  - `channel`: `in_app` or `email`
  - `provider` for email: `resend`

- `notification_preferences`
  - `id`, `user_id`, `social_enabled`, `friendship_enabled`, `wedding_enabled`, `inserted_at`, `updated_at`
  - billing reminders are mandatory and not user-disableable

---

## Phase 4 tables (Apartments)

- `apartments`
  - `id`, `owner_id`, `name`, `theme`, `is_locked`, `inserted_at`, `updated_at`
- `apartment_visits`
  - `id`, `apartment_id`, `visitor_id`, `joined_at`, `left_at`
- `apartment_bans`
  - `id`, `apartment_id`, `user_id`, `reason`, `expires_at`, `inserted_at`

Occupancy limits are runtime rules enforced in service/actor layer:
- apartment cap: `6`

---

## Phase 5 tables (Marriage + Family + House)

- `marriages`
  - `id`, `partner_a_id`, `partner_b_id`, `status`, `started_at`, `ended_at`
  - check constraint: `partner_a_id <> partner_b_id`
  - policy: only one active marriage per user at a time
- `families`
  - `id`, `marriage_id`, `family_name`, `inserted_at`
- `children`
  - `id`, `family_id`, `name`, `age_stage`, `inserted_at`
- `houses`
  - `id`, `family_id`, `name`, `theme`, `garden_style`, `inserted_at`, `updated_at`

Occupancy runtime rule:
- house cap: `12`

---

## Phase 6 tables (Cosmetics + Billing)

- `cosmetic_items`
  - `id`, `sku`, `name`, `slot`, `rarity`, `is_premium`, `inserted_at`
- `user_inventory`
  - `id`, `user_id`, `item_id`, `source`, `inserted_at`
- `subscriptions`
  - `id`, `user_id`, `provider`, `provider_subscription_id`, `status`, `current_period_end`
- `subscription_events`
  - `id`, `provider_event_id`, `user_id`, `event_type`, `payload_json`, `processed_at`
- `media_assets`
  - `id`, `user_id`, `kind`, `r2_key`, `mime_type`, `size_bytes`, `inserted_at`

- `subscription_reminder_state`
  - `id`, `subscription_id`, `window`, `target_date`, `scheduled_at_utc`, `sent_at`, `inserted_at`
  - `window`: `7d` or `2d`
  - `scheduled_at_utc` default policy: 09:00 UTC
  - unique constraint on `(subscription_id, window, target_date)`
  - ensures one reminder per user per reminder window

---

## Indexing starter pack

- `users(email)` unique
- `users(display_name)` unique (or normalized variant)
- `friends(user_low_id, user_high_id)` unique
- `friends(status, user_low_id)`
- `friends(status, user_high_id)`
- `blocks(blocker_id, blocked_id)` unique
- `direct_messages(recipient_id, inserted_at)`
- `notifications(user_id, inserted_at)`
- `notifications(user_id, event_key)` unique
- `notification_deliveries(notification_id, channel, status)`
- `notification_preferences(user_id)` unique
- `apartment_visits(apartment_id, joined_at)`
- `subscriptions(user_id)` unique
- `subscription_events(provider_event_id)` unique

---

## Notes

- Keep writes authoritative on backend only.
- Real-time websocket messages should still commit important state to Postgres.
- Add Redis/Dragonfly later only for distributed presence and short-lived coordination.
