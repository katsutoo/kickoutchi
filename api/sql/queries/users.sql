-- name: CreateUser :one
INSERT INTO users (
    id,
    email,
    password_hash,
    display_name,
    role,
    avatar_metadata
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
)
RETURNING id, email, password_hash, display_name, role, inserted_at, updated_at, email_verified_at, avatar_metadata;

-- name: GetUserByID :one
SELECT id, email, password_hash, display_name, role, inserted_at, updated_at, email_verified_at, avatar_metadata
FROM users
WHERE id = $1;

-- name: LockUserByID :one
SELECT id
FROM users
WHERE id = $1
FOR UPDATE;

-- name: GetUserByEmail :one
SELECT id, email, password_hash, display_name, role, inserted_at, updated_at, email_verified_at, avatar_metadata
FROM users
WHERE lower(email) = lower($1);

-- name: GetUserByDisplayName :one
SELECT id, email, password_hash, display_name, role, inserted_at, updated_at, email_verified_at, avatar_metadata
FROM users
WHERE lower(display_name) = lower($1);

-- name: UpdateUserDisplayName :one
UPDATE users
SET
    display_name = $2,
    updated_at = now()
WHERE id = $1
RETURNING id, email, password_hash, display_name, role, inserted_at, updated_at, email_verified_at, avatar_metadata;

-- name: UpdateUserPasswordHash :one
UPDATE users
SET
    password_hash = $2,
    updated_at = now()
WHERE id = $1
RETURNING id, email, password_hash, display_name, role, inserted_at, updated_at, email_verified_at, avatar_metadata;

-- name: UpdateUserRole :one
UPDATE users
SET
    role = $2,
    updated_at = now()
WHERE id = $1
RETURNING id, email, password_hash, display_name, role, inserted_at, updated_at, email_verified_at, avatar_metadata;

-- name: MarkUserEmailVerified :one
UPDATE users
SET
    email_verified_at = COALESCE(email_verified_at, now()),
    updated_at = now()
WHERE id = $1
RETURNING id, email, password_hash, display_name, role, inserted_at, updated_at, email_verified_at, avatar_metadata;

-- name: UpdateUserProfile :one
UPDATE users
SET
    display_name = $2,
    avatar_metadata = $3,
    updated_at = now()
WHERE id = $1
RETURNING id, email, password_hash, display_name, role, inserted_at, updated_at, email_verified_at, avatar_metadata;
