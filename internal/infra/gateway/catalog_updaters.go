package gateway

import (
	_ "unsafe" // go:linkname
)

// Upstream's service starts its three model catalogue updaters itself, bound to
// the context Run is given (sdk/cliproxy/service_lifecycle.go Service.Run,
// startModelCatalogUpdaters): the models, Codex client models and Devin models
// catalogues, fetched from github.com/router-for-me/models at once and then
// every three hours, unless the process has been switched to the catalogues
// compiled into the build. Its binary makes that switch for --local-model
// (cmd/server/main.go); no SDK package offers it, and it lives in upstream's
// internal/registry, which this module cannot import, so it is pulled by
// linkname: internal/registry/catalog_sources.go SetLocalModelCatalogs,
// func(bool). The linker checks neither the signature nor that the symbol
// still exists under that name, so upgrading upstream must re-check it against
// its source.
//
// The switch only changes the default source. A source set in the
// configuration's models section would still be fetched; that section is
// gateway-owned (settings ownedKeys), so no configuration sets one.

//go:linkname setLocalModelCatalogs github.com/router-for-me/CLIProxyAPI/v8/internal/registry.SetLocalModelCatalogs
func setLocalModelCatalogs(local bool)
