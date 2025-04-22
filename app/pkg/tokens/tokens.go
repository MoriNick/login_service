package tokens

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrEmptySecret             = errors.New("secret is empty")
	ErrAccessInvalidAlg        = errors.New("access token has invalid signing algorithm")
	ErrAccessInvalidSignature  = errors.New("access " + jwt.ErrTokenSignatureInvalid.Error())
	ErrAccessExpired           = errors.New("access " + jwt.ErrTokenExpired.Error())
	ErrEmptyId                 = errors.New("access token has empty id")
	ErrRefreshInvalidAlg       = errors.New("refresh token has invalid signing algorithm")
	ErrRefreshInvalidSignature = errors.New("refresh " + jwt.ErrTokenSignatureInvalid.Error())
	ErrRefreshExpired          = errors.New("refresh " + jwt.ErrTokenExpired.Error())
	ErrEmptyAccessHash         = errors.New("refresh token has empty access_hash")
	ErrInvalidAccessHash       = errors.New("refresh token has invalid access_hash")
)

var (
	accessExpires  = 10 * time.Second
	refreshExpires = 100 * time.Minute
)

var signingMethod = jwt.SigningMethodHS256

type tokens struct {
	access  string
	refresh string
}

func InsertTokens(access, refresh string) *tokens {
	return &tokens{access, refresh}
}

func GenerateTokens(id string) (*tokens, error) {
	if id == "" {
		return nil, ErrEmptyId
	}
	secret, err := getSecret(nil)
	if err != nil {
		return nil, err
	}

	aClaims := &accessClaims{Id: id}
	aClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(accessExpires))
	access, err := jwt.NewWithClaims(signingMethod, aClaims).SignedString(secret)
	if err != nil {
		return nil, err
	}

	rClaims := &refreshClaims{AccessHash: hashAccess(access)}
	rClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(refreshExpires))
	refresh, err := jwt.NewWithClaims(signingMethod, rClaims).SignedString(secret)
	if err != nil {
		return nil, err
	}

	return &tokens{access, refresh}, nil
}

func (t *tokens) Validate() error {
	aClaims := &accessClaims{}
	token, err := jwt.ParseWithClaims(t.access, aClaims, getSecret, jwt.WithoutClaimsValidation())
	if err != nil {
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return ErrAccessInvalidSignature
		}
		return err
	}

	if alg := token.Header["alg"]; alg != signingMethod.Alg() {
		return ErrAccessInvalidAlg
	}

	if err := aClaims.Validate(); err != nil {
		if errors.Is(err, ErrAccessExpired) {
			if err := t.validateRefresh(); err != nil {
				return err
			}
			return ErrAccessExpired
		}
		return err
	}

	return nil
}

func (t *tokens) validateRefresh() error {
	rClaims := &refreshClaims{}
	token, err := jwt.ParseWithClaims(t.refresh, rClaims, getSecret, jwt.WithoutClaimsValidation())
	if err != nil {
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return ErrRefreshInvalidSignature
		}
		return err
	}

	if alg := token.Header["alg"]; alg != signingMethod.Alg() {
		return ErrRefreshInvalidAlg
	}

	if err := rClaims.Validate(t.access); err != nil {
		return err
	}

	return nil
}

func (t *tokens) Refresh() error {
	aClaims := &accessClaims{}
	token, err := jwt.ParseWithClaims(t.access, aClaims, getSecret, jwt.WithoutClaimsValidation())
	if err != nil {
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return ErrAccessInvalidSignature
		}
		return err
	}

	if alg := token.Header["alg"]; alg != signingMethod.Alg() {
		return ErrAccessInvalidAlg
	}

	if aClaims.Id == "" {
		return ErrEmptyId
	}

	t, err = GenerateTokens(aClaims.Id)
	if err != nil {
		return err
	}
	return nil
}

func (t *tokens) GetAccess() string {
	return t.access
}

func (t *tokens) GetRefresh() string {
	return t.refresh
}

func (t *tokens) GetId() string {
	claims := &accessClaims{}
	_, _ = jwt.ParseWithClaims(t.access, claims, getSecret, jwt.WithoutClaimsValidation())
	return claims.Id
}

func hashAccess(token string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
}

func getSecret(token *jwt.Token) (interface{}, error) {
	secret := os.Getenv("JWT_SECRET")
	if len(secret) > 0 {
		return []byte(secret), nil
	}
	return nil, ErrEmptySecret
}
