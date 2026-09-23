package app

import (
	"context"
	"time"
)

// compensationTimeout bounds a compensating write. It is generous for one row and
// short enough that a database that is really down does not hold a request forever.
const compensationTimeout = 5 * time.Second

// compensationContext is the context a compensating write runs under: the request's
// values, none of its cancellation, and a deadline of its own.
//
// A compensation undoes the first half of a unit of work whose second half failed.
// The commonest reason that second half fails is that the client went away, which
// cancels the request context — so a compensation run on that context is skipped in
// exactly the case it exists for.
func compensationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), compensationTimeout)
}
