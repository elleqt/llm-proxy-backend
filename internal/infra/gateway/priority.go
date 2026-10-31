package gateway

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const metadataPriority = "priority"

// priorityFromMetadata accepts our decimal form and integral legacy JSON values.
// Invalid metadata stays neutral instead of gaining a routing preference.
func priorityFromMetadata(metadata map[string]any) int32 {
	switch value := metadata[metadataPriority].(type) {
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 32)
		if err != nil {
			return 0
		}

		return int32(parsed)
	case float64:
		if value < -2147483648 || value > 2147483647 || value != math.Trunc(value) {
			return 0
		}

		return int32(value)
	default:
		return 0
	}
}

// accountPriority describes the attribute the upstream selector actually uses.
func accountPriority(auth *coreauth.Auth) int32 {
	if raw, exists := auth.Attributes[metadataPriority]; exists {
		value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 32)
		if err != nil {
			return 0
		}

		return int32(value)
	}

	return priorityFromMetadata(auth.Metadata)
}

// applyAccountPriority leaves unassigned accounts at upstream's neutral default.
func applyAccountPriority(auth *coreauth.Auth) {
	if _, exists := auth.Metadata[metadataPriority]; !exists {
		return
	}

	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string, 1)
	}

	auth.Attributes[metadataPriority] = strconv.FormatInt(int64(priorityFromMetadata(auth.Metadata)), 10)
}

// setAccountPriority changes both representations without replacing other fields.
func setAccountPriority(auth *coreauth.Auth, priority int32) {
	value := strconv.FormatInt(int64(priority), 10)

	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}

	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string, 1)
	}

	auth.Metadata[metadataPriority] = value
	auth.Attributes[metadataPriority] = value
}

// SetAccountPriority saves a routing preference without changing account availability.
func (g *Gateway) SetAccountPriority(ctx context.Context, id string, priority int32) error {
	g.pushMu.Lock()
	defer g.pushMu.Unlock()

	if g.coreAuth != nil && g.store == nil {
		return ErrNoTokenStore
	}

	reload, held, err := g.accountLocked(id)
	if err != nil {
		return err
	}

	updated, applied, err := g.coreAuth.Modify(ctx, id, held.RegistrationEpoch, func(next *coreauth.Auth) error {
		setAccountPriority(next, priority)

		return g.saveLocked(ctx, next)
	})
	if err != nil {
		return fmt.Errorf("gateway: account %q priority could not be applied: %w", id, err)
	}

	if !applied || updated == nil {
		return fmt.Errorf("%w: %q", ErrUnknownAccount, id)
	}

	if isCompatAccount(updated) {
		g.reapplyLocked(reload)
	}

	return nil
}
