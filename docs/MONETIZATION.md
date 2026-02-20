# Monetization

Monetization should support development without harming gameplay fairness.

---

## Model

- Single premium subscription: `EUR 5.99 / month`
- Payment provider: Polar.sh
- Free tier keeps full gameplay access

---

## Premium includes

- Extra decoration packs (apartment and house)
- Extra outfit cosmetics (clothes, hats, accessories)
- Extra profile cosmetics (frames, badges, emotes)

---

## Premium does NOT include

- No stat boosts
- No faster evolution rates
- No access advantages in social limits
- No PvP or progression power

---

## Entitlement design

- Backend stores subscription status in `subscriptions`
- Polar webhook events update entitlements
- Frontend reads entitlement from authenticated user payload
- Locked items show upgrade prompts instead of hard errors
- Expiry reminders:
  - 7 days before expiry at 09:00 UTC: in-app notification only
  - 2 days before expiry at 09:00 UTC: in-app notification and Resend email
  - one reminder per window via idempotency keys

---

## Failure handling

- If webhook delivery fails, retry and keep event idempotency by event ID
- If subscription expires, keep owned items but disable premium-only active effects
- If user resubscribes, restore premium effects immediately

---

## KPI baseline

- Trial to paid conversion
- Monthly churn
- Premium attachment rate (% active users with premium)
- Revenue per monthly active user
