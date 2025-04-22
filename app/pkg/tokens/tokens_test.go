package tokens

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// Check errors in GenerateTokens function
func TestGenerateTokens(t *testing.T) {
	t.Run("empty_jwt_secret", func(t *testing.T) {
		_, err := GenerateTokens("test_user_id")
		require.Error(t, err)
		require.EqualError(t, err, ErrEmptySecret.Error())
	})

	_ = os.Setenv("JWT_SECRET", "secret_jwt_for_test")

	t.Run("empty_id", func(t *testing.T) {
		_, err := GenerateTokens("")
		require.Error(t, err)
		require.EqualError(t, err, ErrEmptyId.Error())
	})

	os.Clearenv()
}

var bufAccess string

func generateTestAccessToken(secret interface{}, id string, exp time.Duration, method jwt.SigningMethod) string {
	claims := &accessClaims{Id: id}
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(exp))
	token, _ := jwt.NewWithClaims(method, claims).SignedString(secret)
	bufAccess = token
	return token
}

func generateTestRefreshToken(secret interface{}, access string, exp time.Duration, method jwt.SigningMethod) string {
	claims := &refreshClaims{}
	if access != "" {
		claims.AccessHash = hashAccess(access)
	}
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(exp))
	token, _ := jwt.NewWithClaims(method, claims).SignedString(secret)
	bufAccess = ""
	return token
}

// Check errors in Validate function
func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		secret  string
		access  string
		refresh string
		expErr  error
	}{
		{
			name:    "access_another_secret",
			secret:  "secret",
			access:  generateTestAccessToken([]byte("another_secret"), "id", 10*time.Second, jwt.SigningMethodHS256),
			refresh: generateTestRefreshToken([]byte("another_secret"), bufAccess, 10*time.Second, jwt.SigningMethodHS256),
			expErr:  ErrAccessInvalidSignature,
		},
		{
			name:    "refresh_another_secret",
			secret:  "secret",
			access:  generateTestAccessToken([]byte("secret"), "id", -10*time.Second, jwt.SigningMethodHS256),
			refresh: generateTestRefreshToken([]byte("another_secret"), bufAccess, 10*time.Second, jwt.SigningMethodHS256),
			expErr:  ErrRefreshInvalidSignature,
		},
		{
			name:    "another_claims_in_access_token",
			secret:  "secret",
			access:  generateTestAccessToken([]byte("secret"), "", 10*time.Second, jwt.SigningMethodHS256),
			refresh: generateTestRefreshToken([]byte("secret"), "", 10*time.Second, jwt.SigningMethodHS256),
			expErr:  ErrEmptyId,
		},
		{
			name:    "another_claims_in_refresh_token",
			secret:  "secret",
			access:  generateTestAccessToken([]byte("secret"), "id", -10*time.Second, jwt.SigningMethodHS256),
			refresh: generateTestRefreshToken([]byte("secret"), "", 10*time.Second, jwt.SigningMethodHS256),
			expErr:  ErrEmptyAccessHash,
		},
		{
			name:    "invalid_claims_in_refresh_token",
			secret:  "secret",
			access:  generateTestAccessToken([]byte("secret"), "id", -10*time.Second, jwt.SigningMethodHS256),
			refresh: generateTestRefreshToken([]byte("secret"), "sss", 10*time.Second, jwt.SigningMethodHS256),
			expErr:  ErrInvalidAccessHash,
		},
		{
			name:    "access_none_signing_method",
			secret:  "secret",
			access:  generateTestAccessToken(jwt.UnsafeAllowNoneSignatureType, "id", 10*time.Second, jwt.SigningMethodNone),
			refresh: generateTestRefreshToken(jwt.UnsafeAllowNoneSignatureType, bufAccess, 10*time.Second, jwt.SigningMethodNone),
			expErr:  ErrAccessInvalidSignature,
		},
		{
			name:    "refresh_none_signing_method",
			secret:  "secret",
			access:  generateTestAccessToken([]byte("secret"), "id", -10*time.Second, jwt.SigningMethodHS256),
			refresh: generateTestRefreshToken(jwt.UnsafeAllowNoneSignatureType, bufAccess, 10*time.Second, jwt.SigningMethodNone),
			expErr:  ErrRefreshInvalidSignature,
		},
		{
			name:    "access_another_signing_method",
			secret:  "secret",
			access:  generateTestAccessToken([]byte("secret"), "id", 10*time.Second, jwt.SigningMethodHS512),
			refresh: generateTestRefreshToken([]byte("secret"), bufAccess, 10*time.Second, jwt.SigningMethodHS512),
			expErr:  ErrAccessInvalidAlg,
		},
		{
			name:    "refresh_another_signing_method",
			secret:  "secret",
			access:  generateTestAccessToken([]byte("secret"), "id", -10*time.Second, jwt.SigningMethodHS256),
			refresh: generateTestRefreshToken([]byte("secret"), bufAccess, 10*time.Second, jwt.SigningMethodHS512),
			expErr:  ErrRefreshInvalidAlg,
		},
		{
			name:    "access_expired",
			secret:  "secret",
			access:  generateTestAccessToken([]byte("secret"), "id", -10*time.Second, jwt.SigningMethodHS256),
			refresh: generateTestRefreshToken([]byte("secret"), bufAccess, 10*time.Second, jwt.SigningMethodHS256),
			expErr:  ErrAccessExpired,
		},
		{
			name:    "refresh_expired",
			secret:  "secret",
			access:  generateTestAccessToken([]byte("secret"), "id", -10*time.Second, jwt.SigningMethodHS256),
			refresh: generateTestRefreshToken([]byte("secret"), bufAccess, -10*time.Second, jwt.SigningMethodHS256),
			expErr:  ErrRefreshExpired,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			_ = os.Setenv("JWT_SECRET", tCase.secret)
			tks := InsertTokens(tCase.access, tCase.refresh)
			err := tks.Validate()
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
			os.Clearenv()
		})
	}
}

// Check errors in Refresh function
func TestRefresh(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		access string
		expErr error
	}{
		{
			name:   "empty_id",
			secret: "secret",
			access: generateTestAccessToken([]byte("secret"), "", 10*time.Second, jwt.SigningMethodHS256),
			expErr: ErrEmptyId,
		},
		{
			name:   "another_secret",
			secret: "secret",
			access: generateTestAccessToken([]byte("another_secret"), "", 10*time.Second, jwt.SigningMethodHS256),
			expErr: ErrAccessInvalidSignature,
		},
		{
			name:   "another_signing_method",
			secret: "secret",
			access: generateTestAccessToken([]byte("secret"), "", 10*time.Second, jwt.SigningMethodHS512),
			expErr: ErrAccessInvalidAlg,
		},
		{
			name:   "none_signing_method",
			secret: "secret",
			access: generateTestAccessToken(jwt.UnsafeAllowNoneSignatureType, "", 10*time.Second, jwt.SigningMethodNone),
			expErr: ErrAccessInvalidSignature,
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			_ = os.Setenv("JWT_SECRET", tCase.secret)
			tks := InsertTokens(tCase.access, "")
			err := tks.Refresh()
			require.Error(t, err)
			require.EqualError(t, err, tCase.expErr.Error())
			os.Clearenv()
		})
	}
}
