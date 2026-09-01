package httpapi

import (
	"net/http"
	"net/url"

	"github.com/saubhagyabhadhouria/sauth/internal/apierror"
)

func (s *Server) handleGoogleStart(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		writeError(w, r, apierror.InvalidRequest("redirect_uri query parameter is required"))
		return
	}
	project := projectFrom(r.Context())

	authURL, err := s.auth.StartGoogleOAuth(r.Context(), project.ID, redirectURI)
	if err != nil {
		writeError(w, r, mapAuthErr(err))
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// q.Get("error") is non-empty when the user denied consent; passing an empty
	// code to the service consumes the state and fails cleanly at exchange, so
	// the browser still gets bounced back to the app with ?error=.
	appRedirect, authCode, err := s.auth.HandleGoogleCallback(r.Context(), q.Get("code"), q.Get("state"))
	if err != nil {
		if appRedirect != "" {
			http.Redirect(w, r, appendQuery(appRedirect, "error", "oauth_failed"), http.StatusFound)
			return
		}
		writeError(w, r, mapAuthErr(err))
		return
	}
	http.Redirect(w, r, appendQuery(appRedirect, "auth_code", authCode), http.StatusFound)
}

func (s *Server) handleOAuthExchange(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AuthCode string `json:"auth_code"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	if in.AuthCode == "" {
		writeError(w, r, apierror.InvalidRequest("auth_code is required"))
		return
	}
	project := projectFrom(r.Context())

	res, err := s.auth.ExchangeAuthCode(r.Context(), project.ID, in.AuthCode)
	if err != nil {
		writeError(w, r, mapAuthErr(err))
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func appendQuery(base, key, value string) string {
	u, err := url.Parse(base)
	if err != nil {
		sep := "?"
		if len(base) > 0 && (base[len(base)-1] == '?' || base[len(base)-1] == '&') {
			sep = ""
		}
		return base + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}
