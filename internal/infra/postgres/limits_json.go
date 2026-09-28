package postgres

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
)

// storedRule is a spend-limit rule as users.spend_limits and the settings row
// spend_limits hold it.
type storedRule struct {
	WindowMinutes int64   `json:"window_minutes"`
	AmountUSD     float64 `json:"amount_usd"`
}

// EncodeLimits writes set as its stored JSON; an empty set is "[]".
func EncodeLimits(set limits.Set) ([]byte, error) {
	rows := make([]storedRule, 0, len(set))
	for _, r := range set {
		rows = append(rows, storedRule{WindowMinutes: int64(r.Window / time.Minute), AmountUSD: r.AmountUSD})
	}

	raw, err := json.Marshal(rows)
	if err != nil {
		return nil, fmt.Errorf("postgres: encode spend limits: %w", err)
	}

	return raw, nil
}

// DecodeLimits reads what EncodeLimits wrote.
func DecodeLimits(raw []byte) (limits.Set, error) {
	var rows []storedRule
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("postgres: decode spend limits: %w", err)
	}

	set := make(limits.Set, 0, len(rows))
	for _, r := range rows {
		set = append(set, limits.Rule{Window: time.Duration(r.WindowMinutes) * time.Minute, AmountUSD: r.AmountUSD})
	}

	return set, nil
}
