package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"uuid"

	"Vylux/internal/db/dbq"
	"Vylux/internal/encryption"
	apptracing "Vylux/internal/tracing"

	"github.com/labstack/echo/v5"
)

// KeyHandler serves the AES-128 decryption key for encrypted HLS streams.
//
// Endpoint: GET /api/key/:id
//   - Authorization: Bearer {token}
//
// UUID paths resolve the current asset-scoped stream table. Non-UUID paths are
// a read-only compatibility boundary for playlists produced before v2.1. The
// handler verifies the token (HMAC-SHA256 signature, expiration, and source
// hash match), then returns the 16-byte AES key with Cache-Control: no-store.
type KeyHandler struct {
	queries        *dbq.Queries
	keyTokenSecret string
	wrapper        *encryption.KeyWrapper
}

// NewKeyHandler creates a KeyHandler.
func NewKeyHandler(queries *dbq.Queries, keyTokenSecret string, wrapper *encryption.KeyWrapper) *KeyHandler {
	return &KeyHandler{
		queries:        queries,
		keyTokenSecret: keyTokenSecret,
		wrapper:        wrapper,
	}
}

// keyTokenPayload is the JSON structure embedded in the Bearer token.
type keyTokenPayload struct {
	Hash string `json:"hash"`
	Exp  int64  `json:"exp"` // Unix timestamp
}

// Handle serves GET /api/key/:id.
func (h *KeyHandler) Handle(c *echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing key id")
	}

	// Extract token from Authorization header.
	var token string
	if auth := c.Request().Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token = strings.TrimPrefix(auth, "Bearer ")
	}

	if token == "" {
		return c.String(http.StatusUnauthorized, "Unauthorized")
	}

	payload, err := h.verifyToken(token)
	if err != nil {
		return c.String(http.StatusForbidden, "Forbidden")
	}

	// UUID paths are never allowed to fall back to the legacy hash table. This
	// keeps the two identities unambiguous while old hash playlists remain
	// readable until they are explicitly reprocessed.
	ctx := c.Request().Context()
	var sourceHash string
	var wrappedKey, wrapNonce []byte
	var kekVersion string
	if keyID, parseErr := uuid.Parse(id); parseErr == nil {
		row, queryErr := h.queries.GetStreamEncryptionKey(ctx, keyID)
		if queryErr != nil {
			return c.String(http.StatusNotFound, "Not Found")
		}
		sourceHash = row.SourceHash
		wrappedKey = row.WrappedKey
		wrapNonce = row.WrapNonce
		kekVersion = row.KekVersion
	} else {
		// The legacy path itself is the source hash, so preserve the v2.0
		// boundary and reject a mismatched token before revealing row
		// existence. The post-query comparison below still treats the stored
		// hash as authoritative.
		if payload.Hash != id {
			return c.String(http.StatusForbidden, "Forbidden")
		}
		row, queryErr := h.queries.GetLegacyEncryptionKey(ctx, id)
		if queryErr != nil {
			return c.String(http.StatusNotFound, "Not Found")
		}
		sourceHash = row.Hash
		wrappedKey = row.WrappedKey
		wrapNonce = row.WrapNonce
		kekVersion = row.KekVersion
	}

	if payload.Hash != sourceHash {
		return c.String(http.StatusForbidden, "Forbidden")
	}

	aesKey, err := h.wrapper.Unwrap(wrappedKey, wrapNonce, kekVersion)
	if err != nil {
		slog.Error("unwrap encryption key failed", apptracing.LogFields(ctx, "key_id", id, "hash", sourceHash, "error", err)...)
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}

	c.Response().Header().Set("Cache-Control", "no-store")
	return c.Blob(http.StatusOK, "application/octet-stream", aesKey)
}

// verifyToken validates the HMAC-SHA256 token signature and expiration.
//
// Token format: base64url( JSON({ "hash": "...", "exp": <unix> }) ) + "." + base64url( HMAC-SHA256(payload, secret) )
func (h *KeyHandler) verifyToken(token string) (*keyTokenPayload, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	payloadB64, sigB64 := parts[0], parts[1]

	// Decode and verify HMAC signature.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(h.keyTokenSecret))
	mac.Write([]byte(payloadB64)) // sign the base64-encoded payload to avoid canonicalization issues
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expectedSig) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Parse payload.
	var payload keyTokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	// Check expiration.
	if time.Now().Unix() > payload.Exp {
		return nil, fmt.Errorf("token expired")
	}

	return &payload, nil
}
