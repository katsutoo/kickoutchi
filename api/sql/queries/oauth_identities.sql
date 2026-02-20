-- name: CreateOAuthIdentity :one
INSERT INTO oauth_identities (
    id,
    user_id,
    provider,
    provider_uid,
    provider_email
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
)
ON CONFLICT (provider, provider_uid)
DO UPDATE
SET provider_email = EXCLUDED.provider_email
RETURNING id, user_id, provider, provider_uid, provider_email, inserted_at;

-- name: GetOAuthIdentityByProviderUID :one
SELECT id, user_id, provider, provider_uid, provider_email, inserted_at
FROM oauth_identities
WHERE provider = $1
  AND provider_uid = $2;

-- name: ListOAuthIdentitiesByUserID :many
SELECT id, user_id, provider, provider_uid, provider_email, inserted_at
FROM oauth_identities
WHERE user_id = $1
ORDER BY inserted_at ASC;

-- name: GetOAuthIdentityByUserProvider :one
SELECT id, user_id, provider, provider_uid, provider_email, inserted_at
FROM oauth_identities
WHERE user_id = $1
  AND provider = $2;
