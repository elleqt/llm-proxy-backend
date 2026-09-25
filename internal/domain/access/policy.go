package access

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Rule allows one provider and the models matching ModelPattern.
//
// ModelPattern is a glob over the whole model identifier: "*" matches any run of
// characters including "/" and ":", and "?" matches exactly one. It is deliberately
// NOT path.Match — model identifiers are not paths. Real ones carry both separators
// (OpenRouter "openai/gpt-4o", Ollama "llama3:70b", Bedrock "…-v1:0"), and under
// path semantics a natural rule like "*claude*" would silently match none of them.
//
// "*" alone means every model of the provider, including models published after the
// rule was written: the pattern is evaluated per request against the live catalogue,
// never expanded into a list when the rule is granted.
type Rule struct {
	Provider     string
	ModelPattern string

	// re is the compiled form of ModelPattern, built once by ParseRule. A Rule is
	// evaluated on every proxied request against every catalogue entry, so compiling
	// per call would be the hottest allocation in the gate. A hand-built Rule leaves
	// it nil and matches compiles on demand.
	re *regexp.Regexp
}

// Policy is an allow-list. Order is irrelevant: a request is permitted when any
// rule matches. There are deliberately no deny rules.
type Policy []Rule

var ErrMalformedRule = errors.New("access: malformed rule")

// ParseRule splits on the FIRST colon only. The provider half is an operator-chosen
// name and never contains a colon; the model half frequently does, so splitting on
// every colon would make whole providers inexpressible.
func ParseRule(raw string) (Rule, error) {
	provider, pattern, found := strings.Cut(strings.TrimSpace(raw), ":")
	if !found {
		return Rule{}, fmt.Errorf("%w: %q", ErrMalformedRule, raw)
	}

	provider, pattern = strings.TrimSpace(provider), strings.TrimSpace(pattern)
	if provider == "" || pattern == "" {
		return Rule{}, fmt.Errorf("%w: %q", ErrMalformedRule, raw)
	}
	// Every pattern compiles by construction: compileGlob quotes everything that is
	// not "*" or "?", so unlike path.Match there is no such thing as a malformed model
	// glob here. "claude:[opus" is therefore a literal that matches a model actually
	// named "[opus" — predictable rather than silently unmatchable.
	re, err := compileGlob(strings.ToLower(pattern))
	if err != nil {
		//nolint:errorlint // The parser's error is detail: ErrMalformedRule is the only matchable error.
		return Rule{}, fmt.Errorf("%w: %q: %v", ErrMalformedRule, raw, err)
	}

	return Rule{
		Provider:     strings.ToLower(provider),
		ModelPattern: strings.ToLower(pattern),
		re:           re,
	}, nil
}

func (r Rule) String() string { return r.Provider + ":" + r.ModelPattern }

// compileGlob turns a model glob into an anchored regexp: "*" becomes ".*" and "?"
// becomes ".", every other character is quoted. Quoting is what keeps a stored rule
// from smuggling in alternation, anchors or a catastrophic backtrack.
//
// It returns an error only for a pattern that cannot compile, which is why ParseRule
// can use it as a validator.
func compileGlob(pattern string) (*regexp.Regexp, error) {
	var expr strings.Builder
	expr.WriteByte('^')

	for _, char := range pattern {
		switch char {
		case '*':
			expr.WriteString(".*")
		case '?':
			expr.WriteByte('.')
		default:
			expr.WriteString(regexp.QuoteMeta(string(char)))
		}
	}

	expr.WriteByte('$')

	re, err := regexp.Compile(expr.String())
	if err != nil {
		return nil, fmt.Errorf("access: compile glob: %w", err)
	}

	return re, nil
}

func (r Rule) matches(provider, model string) bool {
	// Rules store providers lowercased. EqualFold would also fold non-ASCII runes
	// (U+017F matches "s"), widening an allow-list that must match exactly.
	if r.Provider != "*" && r.Provider != strings.ToLower(provider) { //nolint:gocritic // EqualFold would widen the match
		return false
	}
	// The common grant. Short-circuits before any matching work.
	if r.ModelPattern == "*" {
		return true
	}

	re := r.re
	if re == nil { // hand-built Rule, not produced by ParseRule
		var err error
		if re, err = compileGlob(r.ModelPattern); err != nil {
			return false
		}
	}

	return re.MatchString(strings.ToLower(model))
}

func (p Policy) Allows(provider, model string) bool {
	for _, r := range p {
		if r.matches(provider, model) {
			return true
		}
	}

	return false
}

// Covers reports whether the policy allows model on every one of providers, the
// providers serving it right now. Upstream picks among them when it routes, so
// allowing fewer than all would let a request land on one the policy does not allow.
// A model no provider serves is not covered: the answer fails closed.
func (p Policy) Covers(model string, providers []string) bool {
	if len(providers) == 0 {
		return false
	}

	for _, provider := range providers {
		if !p.Allows(provider, model) {
			return false
		}
	}

	return true
}

// Catalog answers which providers serve a model right now, under the provider
// names policies are written in.
type Catalog interface {
	// ProvidersFor returns every provider serving model; nil if none does.
	ProvidersFor(model string) []string
}

// Admits reports whether a request naming requested gets through: the model it
// resolves to as upstream routes it (Routed) is covered on every provider serving
// it (Covers). It is the one rule the gateway enforces on every proxied request,
// filters every model listing by, and the cabinet lists a user's models by.
func (p Policy) Admits(catalog Catalog, requested string) bool {
	model, providers := Routed(catalog, requested)

	return p.Covers(model, providers)
}

// Routed resolves requested as upstream does before routing
// (sdk/api/handlers/handlers_routing.go getRequestDetailsWithOptions): the name
// without its thinking suffix first, then the full name. It returns the
// registered model the providers were found for. "auto" names whichever model
// upstream finds available first, so it is never resolved.
func Routed(catalog Catalog, requested string) (string, []string) {
	base := thinkingBase(requested)
	if requested == "auto" || base == "auto" {
		return "", nil
	}

	trimmed := strings.TrimSpace(base)
	if providers := catalog.ProvidersFor(trimmed); len(providers) > 0 {
		return trimmed, providers
	}

	if trimmed != requested {
		return requested, catalog.ProvidersFor(requested)
	}

	return trimmed, nil
}

// thinkingBase is the model name without a trailing "(suffix)", as upstream's
// thinking.ParseSuffix splits it.
func thinkingBase(model string) string {
	open := strings.LastIndex(model, "(")
	if open == -1 || !strings.HasSuffix(model, ")") {
		return model
	}

	return model[:open]
}
