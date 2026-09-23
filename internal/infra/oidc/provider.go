// Package oidc is the OpenID Connect relying party behind app.IdentityProvider:
// discovery, the authorization-code flow with PKCE, and ID token verification.
package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

// httpTimeout bounds every request to the IdP: discovery at startup, the token
// exchange and the key fetch during a login. An IdP that accepts the connection and
// never answers must fail the login, not hold a goroutine and a browser forever.
const httpTimeout = 10 * time.Second

// Config is the confidential client this deployment registered at the IdP.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// GroupsClaim names the ID token claim that holds the user's group paths.
	GroupsClaim string
}

// Provider implements app.IdentityProvider.
type Provider struct {
	oauth       oauth2.Config
	verifier    *gooidc.IDTokenVerifier
	client      *http.Client
	groupsClaim string
}

var _ app.IdentityProvider = (*Provider)(nil)

// New discovers the issuer's endpoints and keys. Discovery gets its own deadline on
// top of whatever ctx carries, so an unreachable IdP fails startup promptly instead
// of hanging it.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	client := &http.Client{Timeout: httpTimeout}
	dctx, cancel := context.WithTimeout(gooidc.ClientContext(ctx, client), httpTimeout)
	defer cancel()
	// The provider keeps the client, not the context: key fetches after this
	// returns use the bounded client and are unaffected by cancel.
	p, err := gooidc.NewProvider(dctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	return &Provider{
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       []string{gooidc.ScopeOpenID, "email", "profile"},
		},
		verifier:    p.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
		client:      client,
		groupsClaim: cfg.GroupsClaim,
	}, nil
}

// AuthURL sends the state, the nonce the ID token must echo, and the S256 challenge
// of the verifier only Exchange will reveal.
func (p *Provider) AuthURL(ch app.Challenge) string {
	return p.oauth.AuthCodeURL(ch.State,
		gooidc.Nonce(ch.Nonce),
		oauth2.S256ChallengeOption(ch.Verifier))
}

// Exchange redeems the code with the PKCE verifier and verifies the ID token it
// returns: signature, issuer, audience and expiry through go-oidc, then the nonce.
//
// Anything that is a statement about the credential — the IdP refusing the code, a
// token that fails verification, a nonce from another login — wraps
// app.ErrInvalidCredentials. An IdP that cannot be reached is a plain error. No error
// carries the code, the verifier, a token or the client secret.
func (p *Provider) Exchange(ctx context.Context, code string, ch app.Challenge) (app.Claims, error) {
	ctx = gooidc.ClientContext(ctx, p.client)
	tok, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(ch.Verifier))
	if err != nil {
		return app.Claims{}, exchangeError(err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return app.Claims{}, errors.New("oidc: token response carries no id_token")
	}

	idt, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return app.Claims{}, fmt.Errorf("%w: %v", app.ErrInvalidCredentials, err)
	}
	if ch.Nonce == "" || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(ch.Nonce)) != 1 {
		return app.Claims{}, fmt.Errorf("%w: oidc: id token nonce does not match this login", app.ErrInvalidCredentials)
	}

	var claims map[string]json.RawMessage
	if err := idt.Claims(&claims); err != nil {
		return app.Claims{}, fmt.Errorf("oidc: decode id token claims: %w", err)
	}
	out := app.Claims{Issuer: idt.Issuer, Subject: idt.Subject}
	if v, ok := claims["email"]; ok {
		if err := json.Unmarshal(v, &out.Email); err != nil {
			return app.Claims{}, errors.New("oidc: email claim is not a string")
		}
	}
	// Only the JSON literal true verifies an address. Some providers send the
	// string "true"; reading that as unverified costs an invitation a manual link,
	// reading anything looser as verified could cost an account.
	out.EmailVerified = string(claims["email_verified"]) == "true"
	if v, ok := claims[p.groupsClaim]; ok {
		if err := json.Unmarshal(v, &out.Groups); err != nil {
			return app.Claims{}, fmt.Errorf("oidc: claim %q is not a list of strings", p.groupsClaim)
		}
	}
	return out, nil
}

// exchangeError keeps the IdP's verdict and drops its body. A RetrieveError's
// Error() includes the raw response, which is the IdP's to word and not ours to log.
func exchangeError(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		if re.ErrorCode != "" {
			return fmt.Errorf("%w: oidc: token endpoint refused the code: %s", app.ErrInvalidCredentials, re.ErrorCode)
		}
		status := 0
		if re.Response != nil {
			status = re.Response.StatusCode
		}
		return fmt.Errorf("oidc: token endpoint answered status %d", status)
	}
	return fmt.Errorf("oidc: token exchange: %w", err)
}
