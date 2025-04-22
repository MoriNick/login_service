package middlewares

import (
	"encoding/json"
	"login/pkg/logger"
	"login/pkg/tokens"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func generateTestToken(id string) string {
	if id == "" {
		tks, _ := tokens.GenerateTokens("id")
		return tks.GetRefresh()
	}
	tks, _ := tokens.GenerateTokens(id)
	return tks.GetAccess()
}

func prepareExpResponseBody(st interface{}) string {
	jsonBytes, _ := json.Marshal(st)
	return string(jsonBytes) + "\n"
}

func nextFunc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if targetId := r.Context().Value("user_id"); targetId == nil {
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(
			struct {
				Error string `json:"error"`
			}{Error: "missing user_id field in context"},
		)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(
		struct {
			Message string `json:"message"`
		}{Message: "OK"},
	)
	return
}

func TestAuth(t *testing.T) {
	_ = os.Setenv("JWT_SECRET", "secret")
	defer os.Clearenv()
	_ = logger.GetStubLogger()

	cases := []struct {
		name      string
		access    string
		refresh   string
		expStatus int
		expBody   string
	}{
		{
			name:      "access_is_empty",
			expStatus: http.StatusUnauthorized,
			expBody: prepareExpResponseBody(struct {
				Error string `json:"error"`
			}{"Unauthorized"}),
		},
		{
			name:      "refresh_is_empty",
			access:    generateTestToken("id"),
			expStatus: http.StatusUnauthorized,
			expBody: prepareExpResponseBody(struct {
				Error string `json:"error"`
			}{"Unauthorized"}),
		},
		{
			name:      "refresh_is_expired",
			access:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImlkX3VzZXJfMjU2IiwiZXhwIjoxNzQ0NDU1MjU1fQ.SoO4pxj5jWWFEgcTyg4xT5r0wN-y5Hy-eBrI8jDj7ds",
			refresh:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NfaGFzaCI6ImNmYTM1OTVlMTdkZDg2ODkzMzNkYmUwNmZiNTQ5OTM4MDlkNzczNDQwODUzNzE5NmQzNTQ3YjMzYjJjNzlmMDUiLCJleHAiOjE3NDQ0NTQ2NjV9.kNHK-Cv0KeIH4uHOhI-MyJkx8XJeUNt-06An-D_xcy4",
			expStatus: http.StatusUnauthorized,
			expBody: prepareExpResponseBody(struct {
				Error string `json:"error"`
			}{"Unauthorized"}),
		},
		{
			name:      "invalid_tokens",
			access:    generateTestToken(""),
			refresh:   generateTestToken(""),
			expStatus: http.StatusInternalServerError,
			expBody: prepareExpResponseBody(struct {
				Error string `json:"error"`
			}{"Internal error"}),
		},
		{
			name:      "correct",
			access:    generateTestToken("id"),
			refresh:   generateTestToken(""),
			expStatus: http.StatusOK,
			expBody: prepareExpResponseBody(struct {
				Message string `json:"message"`
			}{"OK"}),
		},
	}

	for _, tCase := range cases {
		t.Run(tCase.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost/api/user", nil)
			if tCase.access != "" {
				req.AddCookie(&http.Cookie{Name: "access_token", Value: tCase.access, HttpOnly: true})
			}
			if tCase.refresh != "" {
				req.AddCookie(&http.Cookie{Name: "refresh_token", Value: tCase.refresh, HttpOnly: true})
			}
			w := httptest.NewRecorder()

			auth := Auth(nextFunc)
			auth(w, req)

			require.Equal(t, tCase.expStatus, w.Code)
			require.Equal(t, tCase.expBody, w.Body.String())
		})
	}
}
