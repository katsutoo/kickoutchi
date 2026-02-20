-- +goose Up
ALTER TABLE users
    ADD COLUMN email_verified_at timestamptz;

ALTER TABLE users
    ADD COLUMN avatar_metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE users
    ADD CONSTRAINT users_avatar_metadata_object_check
    CHECK (jsonb_typeof(avatar_metadata) = 'object');

-- +goose Down
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_avatar_metadata_object_check;

ALTER TABLE users
    DROP COLUMN IF EXISTS avatar_metadata;

ALTER TABLE users
    DROP COLUMN IF EXISTS email_verified_at;
