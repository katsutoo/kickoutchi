# Game Design

This document keeps game rules explicit so implementation stays consistent across backend and frontend.

---

## Core gameplay loops

1. Care loop: feed, clean, play, rest -> pet mood and growth change
2. Social loop: add friends -> visit homes -> chat -> build relationships
3. Progression loop: evolve pet -> unlock cosmetics -> decorate spaces
4. Relationship loop: marry partner -> unlock house -> raise kids

---

## Player and pet rules

- Each account has one primary pet at launch (multi-pet can be added later).
- Pet evolves through stages: `baby -> teen -> adult`.
- Evolution track is selected early and can affect visual identity.
- Starter tracks should be original and broad, for example:
  - Street skater
  - Martial artist
  - Ice performer
- Add more tracks only after core loop retention is stable.

---

## Housing and visits

### Apartment

- Every player starts with an apartment.
- Maximum concurrent visitors: `6`.
- If full, join should return friendly warning text.
- Owner can kick or ban visitors.

### House

- House unlock requires active marriage state.
- Maximum concurrent visitors: `12`.
- House includes garden visuals and expanded decoration slots.

---

## Friends, messaging, and presence

- DM is friend-only.
- Friendship states: `pending`, `accepted`, `declined`.
- Blocking is a separate safety relationship, not a friendship state.
- Presence states: `offline`, `online`, `in_apartment`, `in_house`.
- Tiny in-game phone UI should be the main DM interaction pattern.

---

## Notification rules

- Friendship success: both users receive an in-app notification.
- Wedding success: both partners receive an in-app notification.
- Wedding broadcast: all accepted friends of either partner receive an in-app notification.
- If a player is friend with both partners, they should receive one deduplicated wedding notification.
- Subscription expiry in 7 days: in-app notification only.
- Subscription expiry in 2 days: in-app notification and email via Resend.
- Billing reminders should be idempotent so each user gets one reminder per window.
- Social notifications can be user-configurable; billing reminders are mandatory.

---

## Relationship and family rules

- Marriage is mutual consent only (proposal + accept).
- Same-sex relationships are supported fully.
- Kids are allowed for any married pair in game logic.
- Family state is gameplay-driven, not real-world biology-driven.

---

## Content and art direction constraints

- Avoid direct use of copyrighted character designs.
- Use inspired archetypes and original naming/art.
- Keep style packs distinct, readable, and legally safer.

Safe examples:
- "Space Mechanic Droid" instead of named franchise droids
- "Swamp Ogre Hero" instead of direct film references

---

## Moderation and player safety

- Player-controlled spaces need clear controls: kick, ban, unban.
- Add report and block systems before open launch.
- Enforce chat rate limits and bad-word filtering.

---

## Economy constraints

- Premium should unlock cosmetics, decorations, vanity effects.
- Premium must not improve progression speed or social power.
- Core gameplay stays fully accessible for free users.

---

## Landing page

- Use ASCIIgen.art animations for the public landing page hero and visual accents.
- ASCIIgen ships a React component and plain-text frame files at 3 quality tiers (L/M/H).
- Port the rendering logic to a native Svelte 5 component (`ASCIIAnimation.svelte`) instead of pulling in React.
- Key features to reimplement: frame cycling at configurable FPS, auto-scaling to container, IntersectionObserver pause, `prefers-reduced-motion` respect, quality prop with fallback.
- Animation frame assets live in the SvelteKit app (e.g. `static/animations/` or `$lib/animations/`).
- Pick animations from the included library or generate custom ones with the ASCIIgen live editor.
