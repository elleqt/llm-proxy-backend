// Package usage reads the consumption ledger for the cabinet.
package usage

import (
	"context"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/google/uuid"
)

// Service reads the consumption ledger for the cabinet.
type Service struct {
	usage app.UsageRepo
}

func New(usage app.UsageRepo) *Service { return &Service{usage: usage} }

// Series is userID's own consumption over [from, to), bucketed as UsageRepo
// decides. The caller is the owner: the cabinet shows nobody else's series.
func (s *Service) Series(ctx context.Context, userID uuid.UUID, from, to time.Time) (app.UsageSeries, error) {
	series, err := s.usage.SeriesForUser(ctx, userID, from, to)
	if err != nil {
		return app.UsageSeries{}, fmt.Errorf("app: usage series: %w", err)
	}

	return series, nil
}
