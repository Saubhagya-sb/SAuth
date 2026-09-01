package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/saubhagyabhadhouria/sauth/internal/config"
	"github.com/saubhagyabhadhouria/sauth/internal/googleoauth"
	"github.com/saubhagyabhadhouria/sauth/internal/notify"
	"github.com/saubhagyabhadhouria/sauth/internal/password"
	"github.com/saubhagyabhadhouria/sauth/internal/secretbox"
)

// fakeGoogle stands in for the real Google provider in tests.
type fakeGoogle struct {
	identity *googleoauth.Identity
}

func (f *fakeGoogle) AuthCodeURL(_ googleoauth.Config, state string) string {
	return "https://accounts.google.test/o/oauth2/v2/auth?state=" + url.QueryEscape(state)
}

func (f *fakeGoogle) Exchange(_ context.Context, _ googleoauth.Config, code string) (*googleoauth.Identity, error) {
	if code == "" || f.identity == nil {
		return nil, errors.New("bad code")
	}
	return f.identity, nil
}

var testEncKey = []byte("0123456789abcdef0123456789abcdef") // 32 bytes

// These tests need a reachable Postgres with the SAuth schema already migrated.
// Point SAUTH_TEST_DATABASE_URL at it (falls back to SAUTH_DATABASE_URL). Each
// test provisions and tears down its own org/project, so it won't collide with
// seed data.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SAUTH_TEST_DATABASE_URL")
	if url == "" {
		url = os.Getenv("SAUTH_DATABASE_URL")
	}
	if url == "" {
		t.Skip("set SAUTH_TEST_DATABASE_URL or SAUTH_DATABASE_URL to run integration tests")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Skipf("db unreachable: %v", err)
	}
	// Registered before provisionProject's cleanup, so LIFO closes the pool last.
	t.Cleanup(pool.Close)
	return pool
}

func provisionProject(t *testing.T, pool *pgxpool.Pool) (projectID, apiKey string) {
	t.Helper()
	orgID := uuid.NewString()
	projectID = uuid.NewString()
	roleID := uuid.NewString()
	apiKey = "pk_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	secretHash, _ := password.Hash("test-secret-value")

	mustExec(t, pool, `INSERT INTO organizations (id, name) VALUES ($1, 'itest org')`, orgID)
	mustExec(t, pool, `INSERT INTO projects (id, org_id, name, environment, api_key, api_secret_hash)
		VALUES ($1, $2, 'itest app', 'test', $3, $4)`, projectID, orgID, apiKey, secretHash)
	mustExec(t, pool, `INSERT INTO roles (id, project_id, name, is_default) VALUES ($1, $2, 'member', true)`, roleID, projectID)

	t.Cleanup(func() {
		mustExec(t, pool, `DELETE FROM organizations WHERE id = $1`, orgID) // cascades
	})
	return projectID, apiKey
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func newTestServer(t *testing.T, pool *pgxpool.Pool) (*httptest.Server, *notify.RecordingSender, *fakeGoogle) {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       []byte("integration-test-secret-at-least-32b!"),
		JWTIssuer:       "sauth-itest",
		PublicBaseURL:   "http://sauth.test",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		EncryptionKey:   testEncKey,
	}
	rec := notify.NewRecordingSender()
	fg := &fakeGoogle{}
	srv := httptest.NewServer(NewServer(pool, cfg, WithOTPSender(rec), WithGoogleOAuth(fg)).Routes())
	srv.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.Cleanup(srv.Close)
	return srv, rec, fg
}

// enableGoogle configures a project row with encrypted Google credentials and an
// allowed origin so the OAuth start check passes.
func enableGoogle(t *testing.T, pool *pgxpool.Pool, projectID, allowedOrigin string) {
	t.Helper()
	box, err := secretbox.New(testEncKey)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := box.Seal("test-google-client-secret")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `UPDATE projects
		SET google_oauth_client_id = 'test-client-id.apps.googleusercontent.com',
		    google_oauth_client_secret_enc = $2,
		    allowed_origins = ARRAY[$3::text]
		WHERE id = $1`, projectID, enc, allowedOrigin)
}

type apiResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	OTPID        string `json:"otp_id"`
	User         struct {
		ID    string   `json:"id"`
		Email *string  `json:"email"`
		Roles []string `json:"roles"`
	} `json:"user"`
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

func do(t *testing.T, srv *httptest.Server, method, path, apiKey, bearer, body string) (int, apiResp) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out apiResp
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestPasswordAuthFlow(t *testing.T) {
	pool := testPool(t)
	_, apiKey := provisionProject(t, pool)
	srv, _, _ := newTestServer(t, pool)

	email := "flow-" + uuid.NewString() + "@example.com"

	// signup
	code, r := do(t, srv, "POST", "/v1/auth/signup", apiKey, "",
		`{"email":"`+email+`","username":"flowuser","password":"supersecret1"}`)
	if code != http.StatusCreated {
		t.Fatalf("signup: want 201, got %d (%s)", code, r.Error.Code)
	}
	if len(r.User.Roles) != 1 || r.User.Roles[0] != "member" {
		t.Fatalf("signup: default role not applied: %v", r.User.Roles)
	}
	refresh := r.RefreshToken
	access := r.AccessToken

	// duplicate signup -> 409
	if code, _ := do(t, srv, "POST", "/v1/auth/signup", apiKey, "",
		`{"email":"`+email+`","password":"supersecret1"}`); code != http.StatusConflict {
		t.Fatalf("dup signup: want 409, got %d", code)
	}

	// wrong password -> 401
	if code, r := do(t, srv, "POST", "/v1/auth/login", apiKey, "",
		`{"email_or_username":"flowuser","password":"wrong"}`); code != http.StatusUnauthorized || r.Error.Code != "invalid_credentials" {
		t.Fatalf("bad login: want 401/invalid_credentials, got %d/%s", code, r.Error.Code)
	}

	// me
	if code, r := do(t, srv, "GET", "/v1/auth/me", apiKey, access, ""); code != http.StatusOK || r.User.Email == nil || *r.User.Email != email {
		t.Fatalf("me: want 200 with email, got %d", code)
	}

	// me without token -> 401
	if code, _ := do(t, srv, "GET", "/v1/auth/me", apiKey, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("me no token: want 401, got %d", code)
	}

	// refresh rotates
	code, r = do(t, srv, "POST", "/v1/auth/refresh", apiKey, "", `{"refresh_token":"`+refresh+`"}`)
	if code != http.StatusOK || r.RefreshToken == "" || r.RefreshToken == refresh {
		t.Fatalf("refresh: want 200 with a new token, got %d", code)
	}
	rotated := r.RefreshToken

	// reusing the old token trips reuse detection
	if code, r := do(t, srv, "POST", "/v1/auth/refresh", apiKey, "", `{"refresh_token":"`+refresh+`"}`); code != http.StatusUnauthorized || r.Error.Code != "refresh_token_reuse" {
		t.Fatalf("reuse: want 401/refresh_token_reuse, got %d/%s", code, r.Error.Code)
	}

	// and the whole family is now dead
	if code, _ := do(t, srv, "POST", "/v1/auth/refresh", apiKey, "", `{"refresh_token":"`+rotated+`"}`); code != http.StatusUnauthorized {
		t.Fatalf("post-reuse rotated token: want 401, got %d", code)
	}
}

func TestLogoutInvalidatesRefresh(t *testing.T) {
	pool := testPool(t)
	_, apiKey := provisionProject(t, pool)
	srv, _, _ := newTestServer(t, pool)

	email := "logout-" + uuid.NewString() + "@example.com"
	_, r := do(t, srv, "POST", "/v1/auth/signup", apiKey, "", `{"email":"`+email+`","password":"supersecret1"}`)
	rt := r.RefreshToken

	if code, _ := do(t, srv, "POST", "/v1/auth/logout", apiKey, "", `{"refresh_token":"`+rt+`"}`); code != http.StatusNoContent {
		t.Fatalf("logout: want 204, got %d", code)
	}
	if code, _ := do(t, srv, "POST", "/v1/auth/refresh", apiKey, "", `{"refresh_token":"`+rt+`"}`); code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout: want 401, got %d", code)
	}
}

func TestOTPSignupThenLogin(t *testing.T) {
	pool := testPool(t)
	_, apiKey := provisionProject(t, pool)
	srv, rec, _ := newTestServer(t, pool)

	email := "otp-" + uuid.NewString() + "@example.com"

	// request signup OTP
	code, r := do(t, srv, "POST", "/v1/auth/otp/request", apiKey, "",
		`{"email_or_phone":"`+email+`","purpose":"signup"}`)
	if code != http.StatusOK || r.OTPID == "" {
		t.Fatalf("otp request: want 200 with otp_id, got %d/%s", code, r.Error.Code)
	}
	sent := rec.Code(email)
	if sent == "" {
		t.Fatal("expected a code to be delivered for a new signup")
	}

	// wrong code -> 401 otp_invalid
	if c, rr := do(t, srv, "POST", "/v1/auth/otp/verify", apiKey, "",
		`{"otp_id":"`+r.OTPID+`","code":"000000"}`); c != http.StatusUnauthorized || rr.Error.Code != "otp_invalid" {
		t.Fatalf("wrong code: want 401/otp_invalid, got %d/%s", c, rr.Error.Code)
	}

	// correct code -> account created + tokens
	c, rr := do(t, srv, "POST", "/v1/auth/otp/verify", apiKey, "",
		`{"otp_id":"`+r.OTPID+`","code":"`+sent+`"}`)
	if c != http.StatusOK || rr.AccessToken == "" || rr.User.Email == nil || *rr.User.Email != email {
		t.Fatalf("verify signup: want 200 with tokens+user, got %d/%s", c, rr.Error.Code)
	}
	if len(rr.User.Roles) != 1 || rr.User.Roles[0] != "member" {
		t.Fatalf("verify signup: default role missing: %v", rr.User.Roles)
	}

	// now log in via OTP
	_, r2 := do(t, srv, "POST", "/v1/auth/otp/request", apiKey, "",
		`{"email_or_phone":"`+email+`","purpose":"login"}`)
	if r2.OTPID == "" || rec.Code(email) == "" {
		t.Fatal("login otp: expected code delivered to existing user")
	}
	if c, rr := do(t, srv, "POST", "/v1/auth/otp/verify", apiKey, "",
		`{"otp_id":"`+r2.OTPID+`","code":"`+rec.Code(email)+`"}`); c != http.StatusOK || rr.AccessToken == "" {
		t.Fatalf("verify login: want 200 with tokens, got %d/%s", c, rr.Error.Code)
	}

	// login OTP for an unknown address: still 200 + otp_id, but nothing sent
	unknown := "ghost-" + uuid.NewString() + "@example.com"
	c, r3 := do(t, srv, "POST", "/v1/auth/otp/request", apiKey, "",
		`{"email_or_phone":"`+unknown+`","purpose":"login"}`)
	if c != http.StatusOK || r3.OTPID == "" {
		t.Fatalf("unknown-user otp request: want uniform 200, got %d", c)
	}
	if rec.Code(unknown) != "" {
		t.Fatal("no code should be delivered for an unknown login address")
	}
}

func TestOTPThrottleAndDisabled(t *testing.T) {
	pool := testPool(t)
	projectID, apiKey := provisionProject(t, pool)
	srv, _, _ := newTestServer(t, pool)

	email := "throttle-" + uuid.NewString() + "@example.com"
	if c, _ := do(t, srv, "POST", "/v1/auth/otp/request", apiKey, "",
		`{"email_or_phone":"`+email+`","purpose":"signup"}`); c != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", c)
	}
	if c, rr := do(t, srv, "POST", "/v1/auth/otp/request", apiKey, "",
		`{"email_or_phone":"`+email+`","purpose":"signup"}`); c != http.StatusTooManyRequests || rr.Error.Code != "rate_limited" {
		t.Fatalf("immediate resend: want 429/rate_limited, got %d/%s", c, rr.Error.Code)
	}

	mustExec(t, pool, `UPDATE projects SET otp_enabled = false WHERE id = $1`, projectID)
	if c, rr := do(t, srv, "POST", "/v1/auth/otp/request", apiKey, "",
		`{"email_or_phone":"new-`+email+`","purpose":"signup"}`); c != http.StatusForbidden || rr.Error.Code != "otp_disabled" {
		t.Fatalf("otp disabled: want 403/otp_disabled, got %d/%s", c, rr.Error.Code)
	}
}

// getLocation issues a GET without following redirects and returns the status
// and Location header.
func getLocation(t *testing.T, srv *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

func TestGoogleOAuthFlow(t *testing.T) {
	pool := testPool(t)
	projectID, apiKey := provisionProject(t, pool)
	srv, _, fg := newTestServer(t, pool)

	const appOrigin = "http://localhost:3000"
	enableGoogle(t, pool, projectID, appOrigin)
	fg.identity = &googleoauth.Identity{
		Sub:           "google-sub-" + uuid.NewString(),
		Email:         "guser-" + uuid.NewString() + "@example.com",
		EmailVerified: true,
		Name:          "G User",
	}

	// start -> 302 to Google with a state param
	code, loc := getLocation(t, srv, "/v1/auth/oauth/google/start?api_key="+apiKey+"&redirect_uri="+url.QueryEscape(appOrigin+"/cb"))
	if code != http.StatusFound {
		t.Fatalf("start: want 302, got %d", code)
	}
	gu, _ := url.Parse(loc)
	state := gu.Query().Get("state")
	if state == "" || gu.Host != "accounts.google.test" {
		t.Fatalf("start: unexpected authorize URL %q", loc)
	}

	// disallowed redirect origin -> 403
	if c, _ := getLocation(t, srv, "/v1/auth/oauth/google/start?api_key="+apiKey+"&redirect_uri="+url.QueryEscape("https://evil.example/cb")); c != http.StatusForbidden {
		t.Fatalf("start bad origin: want 403, got %d", c)
	}

	// callback -> 302 back to the app with an auth_code
	code, loc = getLocation(t, srv, "/v1/auth/oauth/google/callback?code=good&state="+url.QueryEscape(state))
	if code != http.StatusFound {
		t.Fatalf("callback: want 302, got %d", code)
	}
	cb, _ := url.Parse(loc)
	if cb.Scheme+"://"+cb.Host+cb.Path != appOrigin+"/cb" {
		t.Fatalf("callback: redirected to %q, want %s/cb", loc, appOrigin)
	}
	authCode := cb.Query().Get("auth_code")
	if authCode == "" {
		t.Fatalf("callback: no auth_code in %q", loc)
	}

	// exchange -> 200 with tokens for the Google user
	c, rr := do(t, srv, "POST", "/v1/auth/oauth/exchange", apiKey, "", `{"auth_code":"`+authCode+`"}`)
	if c != http.StatusOK || rr.AccessToken == "" || rr.User.Email == nil || *rr.User.Email != fg.identity.Email {
		t.Fatalf("exchange: want 200 with tokens+user, got %d/%s", c, rr.Error.Code)
	}
	if len(rr.User.Roles) != 1 || rr.User.Roles[0] != "member" {
		t.Fatalf("exchange: default role missing: %v", rr.User.Roles)
	}

	// auth_code is single-use
	if c, rr := do(t, srv, "POST", "/v1/auth/oauth/exchange", apiKey, "", `{"auth_code":"`+authCode+`"}`); c != http.StatusUnauthorized || rr.Error.Code != "auth_code_invalid" {
		t.Fatalf("exchange reuse: want 401/auth_code_invalid, got %d/%s", c, rr.Error.Code)
	}

	// state is single-use
	if c, l := getLocation(t, srv, "/v1/auth/oauth/google/callback?code=good&state="+url.QueryEscape(state)); c != http.StatusBadRequest {
		t.Fatalf("callback state reuse: want 400, got %d (loc %q)", c, l)
	}

	// second sign-in with the same Google account resolves to the same user
	code, loc = getLocation(t, srv, "/v1/auth/oauth/google/start?api_key="+apiKey+"&redirect_uri="+url.QueryEscape(appOrigin+"/cb"))
	gu, _ = url.Parse(loc)
	code, loc = getLocation(t, srv, "/v1/auth/oauth/google/callback?code=good&state="+url.QueryEscape(gu.Query().Get("state")))
	cb, _ = url.Parse(loc)
	c, rr2 := do(t, srv, "POST", "/v1/auth/oauth/exchange", apiKey, "", `{"auth_code":"`+cb.Query().Get("auth_code")+`"}`)
	if c != http.StatusOK || rr2.User.ID != rr.User.ID {
		t.Fatalf("second sign-in: want same user %s, got %s (status %d)", rr.User.ID, rr2.User.ID, c)
	}
}

func TestOAuthNotConfigured(t *testing.T) {
	pool := testPool(t)
	_, apiKey := provisionProject(t, pool)
	srv, _, _ := newTestServer(t, pool)

	c, _ := getLocation(t, srv, "/v1/auth/oauth/google/start?api_key="+apiKey+"&redirect_uri="+url.QueryEscape("http://localhost:3000/cb"))
	if c != http.StatusBadRequest {
		t.Fatalf("start without google creds: want 400, got %d", c)
	}
}

func TestRequireProject(t *testing.T) {
	pool := testPool(t)
	srv, _, _ := newTestServer(t, pool)

	if code, _ := do(t, srv, "POST", "/v1/auth/login", "", "", `{}`); code != http.StatusUnauthorized {
		t.Fatalf("missing api key: want 401, got %d", code)
	}
	if code, _ := do(t, srv, "POST", "/v1/auth/login", "pk_does_not_exist", "", `{}`); code != http.StatusUnauthorized {
		t.Fatalf("bad api key: want 401, got %d", code)
	}
}
