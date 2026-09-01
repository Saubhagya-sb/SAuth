package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/saubhagyabhadhouria/sauth/internal/apierror"
)

// requireProject resolves the calling project from the X-API-Key header and
// stashes it on the request context. Every /v1/auth route runs behind this.
func (s *Server) requireProject(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Header for API calls; ?api_key= for top-level browser navigations
		// (e.g. the OAuth start redirect) that can't set headers. The publishable
		// key is safe to expose either way.
		key := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if key == "" {
			key = strings.TrimSpace(r.URL.Query().Get("api_key"))
		}
		if key == "" {
			writeError(w, r, apierror.Unauthorized("missing API key (X-API-Key header or api_key query parameter)"))
			return
		}
		project, err := s.q.GetProjectByAPIKey(r.Context(), key)
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, r, apierror.Unauthorized("invalid API key"))
			return
		}
		if err != nil {
			writeError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(withProject(r.Context(), &project)))
	})
}

// requireAccessToken validates a Bearer access token and puts its claims on the
// context. It must run after requireProject; the token's project_id claim is
// checked against the resolved project.
func (s *Server) requireAccessToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r)
		if !ok {
			writeError(w, r, apierror.Unauthorized("missing or malformed Authorization header"))
			return
		}
		claims, err := s.tokens.ParseAccess(raw)
		if err != nil {
			writeError(w, r, apierror.Unauthorized("invalid or expired access token"))
			return
		}
		if p := projectFrom(r.Context()); p != nil && claims.ProjectID != p.ID.String() {
			writeError(w, r, apierror.Unauthorized("access token does not belong to this project"))
			return
		}
		next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), claims)))
	})
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}
