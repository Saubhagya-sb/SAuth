package httpapi

import (
	"context"

	"github.com/saubhagyabhadhouria/sauth/internal/db"
	"github.com/saubhagyabhadhouria/sauth/internal/token"
)

type ctxKey int

const (
	ctxKeyProject ctxKey = iota
	ctxKeyClaims
)

func withProject(ctx context.Context, p *db.Project) context.Context {
	return context.WithValue(ctx, ctxKeyProject, p)
}

func projectFrom(ctx context.Context) *db.Project {
	p, _ := ctx.Value(ctxKeyProject).(*db.Project)
	return p
}

func withClaims(ctx context.Context, c *token.AccessClaims) context.Context {
	return context.WithValue(ctx, ctxKeyClaims, c)
}

func claimsFrom(ctx context.Context) *token.AccessClaims {
	c, _ := ctx.Value(ctxKeyClaims).(*token.AccessClaims)
	return c
}
