// Package httpapi wires the HTTP router and its dependencies.
package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/saubhagyabhadhouria/sauth/internal/auth"
	"github.com/saubhagyabhadhouria/sauth/internal/config"
	"github.com/saubhagyabhadhouria/sauth/internal/db"
	"github.com/saubhagyabhadhouria/sauth/internal/token"
)

type Server struct {
	pool   *pgxpool.Pool
	q      *db.Queries
	tokens *token.Issuer
	auth   *auth.Service
}

func NewServer(pool *pgxpool.Pool, cfg *config.Config) *Server {
	issuer := token.NewIssuer(cfg.JWTSecret, cfg.JWTIssuer, cfg.AccessTokenTTL)
	return &Server{
		pool:   pool,
		q:      db.New(pool),
		tokens: issuer,
		auth:   auth.NewService(pool, issuer, cfg.RefreshTokenTTL),
	}
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(requestLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/healthz", s.handleHealth)
	r.Get("/readyz", s.handleReady)

	r.Route("/v1", func(r chi.Router) {
		r.Mount("/auth", s.authRouter())
	})

	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.pool.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "db_unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
