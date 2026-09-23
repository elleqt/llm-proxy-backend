package app

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// UsageService reads the consumption ledger for the cabinet.
type UsageService struct {
	usage UsageRepo
}

func NewUsageService(usage UsageRepo) *UsageService { return &UsageService{usage: usage} }

// Series is userID's own consumption over [from, to), bucketed as UsageRepo
// decides. The caller is the owner: the cabinet shows nobody else's series.
func (s *UsageService) Series(ctx context.Context, userID uuid.UUID, from, to time.Time) (UsageSeries, error) {
	return s.usage.SeriesForUser(ctx, userID, from, to)
}
