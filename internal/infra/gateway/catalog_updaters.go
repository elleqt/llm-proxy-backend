package gateway

import (
	"context"

	_ "unsafe" // go:linkname
)

// The upstream binary keeps its model catalogue current by starting three
// updaters from its command, not from the SDK service (v7.3.18
// cmd/server/main.go:824 and :840-853 startModelCatalogUpdaters): each fetches
// its catalogue from github.com/router-for-me/models at once and then every
// three hours, and the service re-registers the models of every account whose
// provider changed (sdk/cliproxy/service_plugins.go:322
// registerModelRefreshCallback, which also receives changes found before it
// was registered). An embedder that does not start them serves only the
// catalogue compiled into the build.
//
// They live in upstream's internal/registry, which this module cannot import,
// and no SDK package starts or wraps them, so they are pulled by linkname:
// internal/registry/model_updater.go:78 StartModelsUpdater,
// codex_client_models_updater.go:25 StartCodexClientModelsUpdater and
// devin_models_updater.go:25 StartDevinModelsUpdater, each
// func(context.Context). The linker checks neither the signature nor that the
// symbol still exists under that name, so upgrading upstream must re-check all
// three against its source.

//go:linkname startModelsUpdater github.com/router-for-me/CLIProxyAPI/v7/internal/registry.StartModelsUpdater
func startModelsUpdater(ctx context.Context)

//go:linkname startCodexClientModelsUpdater github.com/router-for-me/CLIProxyAPI/v7/internal/registry.StartCodexClientModelsUpdater
func startCodexClientModelsUpdater(ctx context.Context)

//go:linkname startDevinModelsUpdater github.com/router-for-me/CLIProxyAPI/v7/internal/registry.StartDevinModelsUpdater
func startDevinModelsUpdater(ctx context.Context)

// StartModelCatalogUpdaters starts upstream's model catalogue updaters as its
// binary does without a local model file and outside home mode, which the
// gateway refuses (modelCatalogUpdaterPlan(false, false) starts all three).
// They fetch over the network immediately.
//
// Each updater runs at most once per process (a sync.Once apiece): the first
// call's ctx governs them, cancelling it stops their periodic refresh, and
// later calls do nothing, even after that ctx has ended.
func StartModelCatalogUpdaters(ctx context.Context) {
	startCodexClientModelsUpdater(ctx)
	startDevinModelsUpdater(ctx)
	startModelsUpdater(ctx)
}
