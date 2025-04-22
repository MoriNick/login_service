package tokens

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type accessClaims struct {
	Id string `json:"id"`
	jwt.RegisteredClaims
}

type refreshClaims struct {
	AccessHash string `json:"access_hash"`
	jwt.RegisteredClaims
}

func (a *accessClaims) Validate() error {
	exp, _ := a.GetExpirationTime()
	now := time.Now()

	if a.Id == "" {
		return ErrEmptyId
	}
	if !now.Before(exp.Time) {
		return ErrAccessExpired
	}

	return nil
}

func (r *refreshClaims) Validate(access string) error {
	exp, _ := r.GetExpirationTime()
	now := time.Now()

	if r.AccessHash == "" {
		return ErrEmptyAccessHash
	}
	if r.AccessHash != hashAccess(access) {
		return ErrInvalidAccessHash
	}
	if !now.Before(exp.Time) {
		return ErrRefreshExpired
	}

	return nil
}
