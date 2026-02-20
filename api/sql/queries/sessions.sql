-- name: CreateSession :one
INSERT INTO sessions (
    id,
    user_id,
    token_hash,
    expires_at,
    ip_address,
    user_agent
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
)
RETURNING id, user_id, token_hash, expires_at, ip_address, user_agent, inserted_at;

-- name: GetSessionByTokenHash :one
SELECT id, user_id, token_hash, expires_at, ip_address, user_agent, inserted_at
FROM sessions
WHERE token_hash = $1;

-- name: GetSessionByTokenHashActive :one
SELECT id, user_id, token_hash, expires_at, ip_address, user_agent, inserted_at
FROM sessions
WHERE token_hash = $1
  AND expires_at > now();

-- name: UpdateSessionExpiresAt :one
UPDATE sessions
SET expires_at = $2
WHERE id = $1
RETURNING id, user_id, token_hash, expires_at, ip_address, user_agent, inserted_at;

-- name: DeleteSessionByTokenHash :exec
DELETE FROM sessions
WHERE token_hash = $1;

-- name: DeleteSessionByID :exec
DELETE FROM sessions
WHERE id = $1;

-- name: DeleteSessionsByUserID :exec
DELETE FROM sessions
WHERE user_id = $1;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions
WHERE expires_at <= now();
