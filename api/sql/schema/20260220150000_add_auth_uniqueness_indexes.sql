-- +goose Up
CREATE UNIQUE INDEX oauth_identities_user_provider_unique_idx
    ON oauth_identities (user_id, provider);

CREATE UNIQUE INDEX email_tokens_user_type_active_unique_idx
    ON email_tokens (user_id, type)
    WHERE used_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS email_tokens_user_type_active_unique_idx;
DROP INDEX IF EXISTS oauth_identities_user_provider_unique_idx;
