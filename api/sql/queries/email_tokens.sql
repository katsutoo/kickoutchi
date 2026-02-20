-- name: CreateEmailToken :one
INSERT INTO email_tokens (
    id,
    user_id,
    token_hash,
    type,
    expires_at
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
)
RETURNING id, user_id, token_hash, type, expires_at, used_at, inserted_at;

-- name: GetEmailTokenByHash :one
SELECT id, user_id, token_hash, type, expires_at, used_at, inserted_at
FROM email_tokens
WHERE token_hash = $1;

-- name: GetEmailTokenByHashActive :one
SELECT id, user_id, token_hash, type, expires_at, used_at, inserted_at
FROM email_tokens
WHERE token_hash = $1
  AND used_at IS NULL
  AND expires_at > now();

-- name: GetEmailTokenByHashActiveType :one
SELECT id, user_id, token_hash, type, expires_at, used_at, inserted_at
FROM email_tokens
WHERE token_hash = $1
  AND type = $2
  AND used_at IS NULL
  AND expires_at > now();

-- name: MarkEmailTokenUsed :one
UPDATE email_tokens
SET used_at = now()
WHERE id = $1
  AND used_at IS NULL
RETURNING id, user_id, token_hash, type, expires_at, used_at, inserted_at;

-- name: InvalidateActiveEmailTokensByUserAndType :exec
UPDATE email_tokens
SET used_at = now()
WHERE user_id = $1
  AND type = $2
  AND used_at IS NULL;

-- name: DeleteEmailTokensByUserID :exec
DELETE FROM email_tokens
WHERE user_id = $1;

-- name: DeleteExpiredEmailTokens :execrows
DELETE FROM email_tokens
WHERE expires_at <= now();
