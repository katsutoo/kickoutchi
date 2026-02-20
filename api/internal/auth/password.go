package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidPasswordHash = errors.New("invalid password hash")
	ErrPasswordEmpty       = errors.New("password cannot be empty")
)

type Argon2Params struct {
	Memory     uint32
	Time       uint32
	Threads    uint8
	KeyLength  uint32
	SaltLength uint32
}

type Argon2Hasher struct {
	params Argon2Params
}

func NewArgon2Hasher(params Argon2Params) *Argon2Hasher {
	return &Argon2Hasher{params: params.withDefaults()}
}

func (h *Argon2Hasher) Hash(password string) (string, error) {
	if password == "" {
		return "", ErrPasswordEmpty
	}

	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, h.params.Time, h.params.Memory, h.params.Threads, h.params.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.params.Memory,
		h.params.Time,
		h.params.Threads,
		b64Salt,
		b64Hash,
	)

	return encoded, nil
}

func (h *Argon2Hasher) Verify(password, encodedHash string) (bool, error) {
	if password == "" {
		return false, ErrPasswordEmpty
	}

	params, salt, expectedHash, err := parseEncodedHash(encodedHash)
	if err != nil {
		return false, err
	}

	computedHash := argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, params.KeyLength)
	if subtle.ConstantTimeCompare(expectedHash, computedHash) == 1 {
		return true, nil
	}

	return false, nil
}

func parseEncodedHash(encodedHash string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}

	if parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}

	versionPart := parts[2]
	versionRaw := strings.TrimPrefix(versionPart, "v=")
	version, err := strconv.Atoi(versionRaw)
	if err != nil || version != argon2.Version {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}

	paramsPart := strings.Split(parts[3], ",")
	if len(paramsPart) != 3 {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}

	memory, err := parseUIntParam(paramsPart[0], "m=", 32)
	if err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}

	timeCost, err := parseUIntParam(paramsPart[1], "t=", 32)
	if err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}

	threads, err := parseUIntParam(paramsPart[2], "p=", 8)
	if err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) == 0 {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}

	params := Argon2Params{
		Memory:     uint32(memory),
		Time:       uint32(timeCost),
		Threads:    uint8(threads),
		KeyLength:  uint32(len(hash)),
		SaltLength: uint32(len(salt)),
	}

	return params, salt, hash, nil
}

func parseUIntParam(value, prefix string, bitSize int) (uint64, error) {
	if !strings.HasPrefix(value, prefix) {
		return 0, ErrInvalidPasswordHash
	}

	raw := strings.TrimPrefix(value, prefix)
	parsed, err := strconv.ParseUint(raw, 10, bitSize)
	if err != nil || parsed == 0 {
		return 0, ErrInvalidPasswordHash
	}

	return parsed, nil
}

func (p Argon2Params) withDefaults() Argon2Params {
	if p.Memory == 0 {
		p.Memory = 19456
	}

	if p.Time == 0 {
		p.Time = 2
	}

	if p.Threads == 0 {
		p.Threads = 1
	}

	if p.KeyLength == 0 {
		p.KeyLength = 32
	}

	if p.SaltLength == 0 {
		p.SaltLength = 16
	}

	return p
}
