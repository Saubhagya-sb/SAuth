package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/saubhagyabhadhouria/sauth/internal/config"
	"github.com/saubhagyabhadhouria/sauth/internal/password"
)

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

func newTestServer(t *testing.T, pool *pgxpool.Pool) *httptest.Server {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       []byte("integration-test-secret-at-least-32b!"),
		JWTIssuer:       "sauth-itest",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
	}
	srv := httptest.NewServer(NewServer(pool, cfg).Routes())
	t.Cleanup(srv.Close)
	return srv
}

type apiResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
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
	srv := newTestServer(t, pool)

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
	srv := newTestServer(t, pool)

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

func TestRequireProject(t *testing.T) {
	pool := testPool(t)
	srv := newTestServer(t, pool)

	if code, _ := do(t, srv, "POST", "/v1/auth/login", "", "", `{}`); code != http.StatusUnauthorized {
		t.Fatalf("missing api key: want 401, got %d", code)
	}
	if code, _ := do(t, srv, "POST", "/v1/auth/login", "pk_does_not_exist", "", `{}`); code != http.StatusUnauthorized {
		t.Fatalf("bad api key: want 401, got %d", code)
	}
}
