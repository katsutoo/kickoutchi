package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/katsutoo/kickoutchi/api/internal/database/sqlc"
)

func (r *AuthRepository) GetOAuthIdentityByProviderUID(ctx context.Context, provider, providerUID string) (OAuthIdentity, error) {
	storedIdentity, err := r.queries.GetOAuthIdentityByProviderUID(ctx, sqlc.GetOAuthIdentityByProviderUIDParams{
		Provider:    provider,
		ProviderUid: providerUID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OAuthIdentity{}, ErrOAuthIdentityNotFound
		}

		return OAuthIdentity{}, fmt.Errorf("get oauth identity by provider uid: %w", err)
	}

	identity, err := fromSQLCOAuthIdentity(storedIdentity)
	if err != nil {
		return OAuthIdentity{}, fmt.Errorf("map oauth identity by provider uid: %w", err)
	}

	return identity, nil
}

func (r *AuthRepository) CreateOAuthIdentity(ctx context.Context, params CreateOAuthIdentityParams) (OAuthIdentity, error) {
	createdIdentity, err := r.queries.CreateOAuthIdentity(ctx, sqlc.CreateOAuthIdentityParams{
		ID:            toPgUUID(params.ID),
		UserID:        toPgUUID(params.UserID),
		Provider:      params.Provider,
		ProviderUid:   params.ProviderUID,
		ProviderEmail: params.ProviderEmail,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if pgErr.ConstraintName == "oauth_identities_user_provider_unique_idx" {
				return OAuthIdentity{}, ErrOAuthProviderLinked
			}
		}

		return OAuthIdentity{}, fmt.Errorf("create oauth identity: %w", err)
	}

	identity, err := fromSQLCOAuthIdentity(createdIdentity)
	if err != nil {
		return OAuthIdentity{}, fmt.Errorf("map created oauth identity: %w", err)
	}

	return identity, nil
}
