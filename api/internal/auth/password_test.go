package auth

import (
	"errors"
	"strings"
	"testing"
)

func testArgon2Hasher() *Argon2Hasher {
	return NewArgon2Hasher(Argon2Params{
		Memory:     64,
		Time:       1,
		Threads:    1,
		KeyLength:  32,
		SaltLength: 16,
	})
}

func TestArgon2HasherHashVerifyRoundTrip(t *testing.T) {
	hasher := testArgon2Hasher()

	encodedHash, err := hasher.Hash("Str0ngPassw0rd!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	if !strings.HasPrefix(encodedHash, "$argon2id$") {
		t.Fatalf("unexpected hash format: %s", encodedHash)
	}

	ok, err := hasher.Verify("Str0ngPassw0rd!", encodedHash)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}

	if !ok {
		t.Fatal("expected password verification to succeed")
	}
}

func TestArgon2HasherVerifyRejectsWrongPassword(t *testing.T) {
	hasher := testArgon2Hasher()

	encodedHash, err := hasher.Hash("Str0ngPassw0rd!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	ok, err := hasher.Verify("Wr0ngPassw0rd!", encodedHash)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}

	if ok {
		t.Fatal("expected verification to fail for wrong password")
	}
}

func TestArgon2HasherVerifyRejectsTamperedHash(t *testing.T) {
	hasher := testArgon2Hasher()

	encodedHash, err := hasher.Hash("Str0ngPassw0rd!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		t.Fatalf("unexpected encoded hash parts: got=%d expected=6", len(parts))
	}

	replacement := "A"
	if strings.HasPrefix(parts[5], replacement) {
		replacement = "B"
	}
	parts[5] = replacement + parts[5][1:]
	tamperedHash := strings.Join(parts, "$")

	ok, err := hasher.Verify("Str0ngPassw0rd!", tamperedHash)
	if err != nil {
		t.Fatalf("verify tampered hash: %v", err)
	}

	if ok {
		t.Fatal("expected verification to fail for tampered hash")
	}
}

func TestArgon2HasherRejectsInvalidHashFormat(t *testing.T) {
	hasher := testArgon2Hasher()

	_, err := hasher.Verify("Str0ngPassw0rd!", "not-a-valid-hash")
	if !errors.Is(err, ErrInvalidPasswordHash) {
		t.Fatalf("expected ErrInvalidPasswordHash, got: %v", err)
	}
}

func TestArgon2HasherRejectsEmptyPassword(t *testing.T) {
	hasher := testArgon2Hasher()

	if _, err := hasher.Hash(""); !errors.Is(err, ErrPasswordEmpty) {
		t.Fatalf("expected ErrPasswordEmpty from Hash, got: %v", err)
	}

	ok, err := hasher.Verify("", "$argon2id$v=19$m=64,t=1,p=1$YWJj$ZGVm")
	if !errors.Is(err, ErrPasswordEmpty) {
		t.Fatalf("expected ErrPasswordEmpty from Verify, got: %v", err)
	}

	if ok {
		t.Fatal("expected empty password verification to fail")
	}
}
