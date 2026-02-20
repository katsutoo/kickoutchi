-- +goose Up
CREATE TABLE users (
    id uuid PRIMARY KEY,
    email text NOT NULL,
    password_hash text NOT NULL,
    display_name text NOT NULL,
    role text NOT NULL DEFAULT 'user',
    inserted_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_role_check CHECK (role IN ('user', 'moderator', 'admin')),
    CONSTRAINT users_email_not_blank CHECK (btrim(email) <> ''),
    CONSTRAINT users_display_name_not_blank CHECK (btrim(display_name) <> '')
);

CREATE UNIQUE INDEX users_email_unique_idx ON users (lower(email));
CREATE UNIQUE INDEX users_display_name_unique_idx ON users (lower(display_name));

CREATE TABLE oauth_identities (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider text NOT NULL,
    provider_uid text NOT NULL,
    provider_email text NOT NULL,
    inserted_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oauth_identities_provider_check CHECK (provider IN ('github', 'google', 'x')),
    CONSTRAINT oauth_identities_provider_uid_not_blank CHECK (btrim(provider_uid) <> ''),
    CONSTRAINT oauth_identities_provider_email_not_blank CHECK (btrim(provider_email) <> '')
);

CREATE UNIQUE INDEX oauth_identities_provider_uid_unique_idx
    ON oauth_identities (provider, provider_uid);

CREATE INDEX oauth_identities_user_id_idx ON oauth_identities (user_id);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    ip_address text,
    user_agent text,
    inserted_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sessions_token_hash_not_empty CHECK (octet_length(token_hash) > 0)
);

CREATE UNIQUE INDEX sessions_token_hash_unique_idx ON sessions (token_hash);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE email_tokens (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash bytea NOT NULL,
    type text NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    inserted_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT email_tokens_type_check CHECK (type IN ('email_verification', 'password_reset')),
    CONSTRAINT email_tokens_token_hash_not_empty CHECK (octet_length(token_hash) > 0)
);

CREATE UNIQUE INDEX email_tokens_token_hash_unique_idx ON email_tokens (token_hash);
CREATE INDEX email_tokens_user_id_idx ON email_tokens (user_id);
CREATE INDEX email_tokens_expires_at_idx ON email_tokens (expires_at);

-- +goose Down
DROP TABLE IF EXISTS email_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS oauth_identities;
DROP TABLE IF EXISTS users;
