package client

import "context"

type ctxKey struct{}

// RequestAuth is the per-call oCIS credential, taken from the user's
// consented grant. When present it overrides the process-wide app token.
type RequestAuth struct {
	OcisAccessToken string
	GrantID         string
}

func WithAuth(ctx context.Context, a RequestAuth) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
}

func AuthFrom(ctx context.Context) (RequestAuth, bool) {
	a, ok := ctx.Value(ctxKey{}).(RequestAuth)
	return a, ok && a.OcisAccessToken != ""
}
