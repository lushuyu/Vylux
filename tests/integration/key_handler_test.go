package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"uuid"

	"Vylux/internal/db/dbq"
	"Vylux/internal/encryption"
)

func TestKeyHandler_CurrentAndLegacyKeyDelivery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts, cfg, _, queries, _, cleanup := newS3BackedTestServerWithDeps(t)
	defer cleanup()

	tests := []struct {
		name string
		hash string
		path string
	}{
		{
			name: "current UUID stream key",
			hash: strings.Repeat("a", 64),
		},
		{
			name: "legacy hash key",
			hash: strings.Repeat("b", 64),
		},
	}
	tests[0].path = seedEncryptionKey(t, cfg.EncryptionKey, queries, tests[0].hash, encryption.AssetTypeVideo)
	seedLegacyEncryptionKey(t, cfg.EncryptionKey, tests[1].hash)
	tests[1].path = tests[1].hash

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := generateKeyToken(tt.hash, cfg.KeyTokenSecret, time.Hour)
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/key/"+tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("GET /api/key/:id: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want 200: %s", resp.StatusCode, body)
			}
			if got := resp.Header.Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read key response: %v", err)
			}
			if string(body) != "0123456789abcdef" {
				t.Fatalf("unexpected unwrapped key bytes: %x", body)
			}
		})
	}
}

func TestKeyHandler_LegacyHashMismatchRejectedBeforeLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts, cfg, _, _, _, cleanup := newS3BackedTestServerWithDeps(t)
	defer cleanup()

	hash := strings.Repeat("c", 64)
	token := generateKeyToken(strings.Repeat("d", 64), cfg.KeyTokenSecret, time.Hour)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/key/"+hash, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/key/:id: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestKeyHandler_UUIDPathNeverFallsBackToLegacy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts, cfg, _, _, _, cleanup := newS3BackedTestServerWithDeps(t)
	defer cleanup()

	legacyHash := "55555555-5555-4555-8555-555555555555"
	seedLegacyEncryptionKey(t, cfg.EncryptionKey, legacyHash)
	token := generateKeyToken(legacyHash, cfg.KeyTokenSecret, time.Hour)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/key/"+legacyHash, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/key/:id: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// TestKeyHandler_NoToken verifies 401 without a token.
func TestKeyHandler_NoToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts, _, cleanup := newTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/api/key/some-key")
	if err != nil {
		t.Fatalf("GET /api/key/:id: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// TestKeyHandler_InvalidToken verifies 403 with an invalid token.
func TestKeyHandler_InvalidToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts, cfg, _, queries, _, cleanup := newS3BackedTestServerWithDeps(t)
	defer cleanup()

	keyID := seedEncryptionKey(t, cfg.EncryptionKey, queries, "some-hash", encryption.AssetTypeVideo)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/key/"+keyID, nil)
	req.Header.Set("Authorization", "Bearer invalid.token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/key/:id: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

// TestKeyHandler_ExpiredToken verifies 403 with an expired token.
func TestKeyHandler_ExpiredToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts, cfg, _, queries, _, cleanup := newS3BackedTestServerWithDeps(t)
	defer cleanup()

	hash := "expired-token-hash"
	keyID := seedEncryptionKey(t, cfg.EncryptionKey, queries, hash, encryption.AssetTypeVideo)
	token := generateKeyToken(hash, cfg.KeyTokenSecret, -1*time.Hour)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/key/"+keyID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/key/:id: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

// TestKeyHandler_HashMismatch verifies 403 when token hash doesn't match URL hash.
func TestKeyHandler_HashMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts, cfg, _, queries, _, cleanup := newS3BackedTestServerWithDeps(t)
	defer cleanup()

	keyID := seedEncryptionKey(t, cfg.EncryptionKey, queries, "correct-hash", encryption.AssetTypeVideo)
	token := generateKeyToken("wrong-hash", cfg.KeyTokenSecret, 1*time.Hour)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/key/"+keyID, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/key/:id: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

// generateKeyToken creates a signed key token for testing.
// Format: base64url(JSON{hash,exp}) + "." + base64url(HMAC-SHA256)
func generateKeyToken(hash, secret string, ttl time.Duration) string {
	type tokenPayload struct {
		Hash string `json:"hash"`
		Exp  int64  `json:"exp"`
	}

	payload := tokenPayload{
		Hash: hash,
		Exp:  time.Now().Add(ttl).Unix(),
	}

	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payloadB64))
	sig := mac.Sum(nil)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return payloadB64 + "." + sigB64
}

func seedEncryptionKey(t *testing.T, encryptionKey string, queries *dbq.Queries, hash, assetType string) string {
	t.Helper()

	wrapper, err := encryption.NewKeyWrapper(encryptionKey)
	if err != nil {
		t.Fatalf("new key wrapper: %v", err)
	}

	wrappedKey, wrapNonce, kekVersion, err := wrapper.Wrap([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}

	keyID := uuid.New()
	if _, err := queries.UpsertStreamEncryptionKey(context.Background(), dbq.UpsertStreamEncryptionKeyParams{
		ID:            keyID,
		SourceHash:    hash,
		AssetType:     assetType,
		PackagingType: encryption.PackagingTypeHLS,
		WrappedKey:    wrappedKey,
		WrapNonce:     wrapNonce,
		KekVersion:    kekVersion,
		Kid:           "kid",
		Scheme:        encryption.DefaultProtectionScheme,
	}); err != nil {
		t.Fatalf("seed encryption key: %v", err)
	}

	return keyID.String()
}

func seedLegacyEncryptionKey(t *testing.T, encryptionKey, hash string) {
	t.Helper()

	wrapper, err := encryption.NewKeyWrapper(encryptionKey)
	if err != nil {
		t.Fatalf("new key wrapper: %v", err)
	}
	wrappedKey, wrapNonce, kekVersion, err := wrapper.Wrap([]byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("wrap legacy key: %v", err)
	}
	if _, err := integrationEnv.pool.Exec(
		context.Background(),
		`INSERT INTO encryption_keys
		 (hash, wrapped_key, wrap_nonce, kek_version, kid, scheme, key_uri)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		hash,
		wrappedKey,
		wrapNonce,
		kekVersion,
		"legacy-kid",
		encryption.DefaultProtectionScheme,
		"/api/key/"+hash,
	); err != nil {
		t.Fatalf("seed legacy encryption key: %v", err)
	}
}
