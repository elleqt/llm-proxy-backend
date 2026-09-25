package boot

import (
	"regexp"
	"runtime/debug"
	"strings"
)

// cliproxyModule is the module path of the embedded CLIProxyAPI.
const cliproxyModule = "github.com/router-for-me/CLIProxyAPI/v7"

// unknownVersion labels a build whose version cannot be told.
const unknownVersion = "unknown"

// resolveVersion returns the label for logs and llmproxy_build_info: the
// injected build version when set, else the module version when it names a
// clean tag, else the VCS commit's short sha, else "unknown".
func resolveVersion(injected string) string {
	bi, _ := debug.ReadBuildInfo()

	return versionOf(injected, bi)
}

// versionOf is resolveVersion over the given build information, which is nil
// when the binary carries none.
func versionOf(injected string, bi *debug.BuildInfo) string {
	if injected != "" {
		return injected
	}

	if bi == nil {
		return unknownVersion
	}
	// Since Go 1.24 go build in a checkout stamps the module version from VCS:
	// a tag, or on an untagged commit a pseudo-version, with +dirty for
	// uncommitted changes. Only a clean tag names the build better than its
	// commit; without VCS information the version is "(devel)".
	if v := bi.Main.Version; v != "" && v != "(devel)" && !pseudoVersion.MatchString(v) && !strings.HasSuffix(v, "+dirty") {
		return v
	}

	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			return s.Value[:min(8, len(s.Value))]
		}
	}

	return unknownVersion
}

// pseudoVersion matches the timestamp and commit a pseudo-version carries
// (v0.1.4-0.20260925101010-abdd1e6abcde); no tag of this module does.
var pseudoVersion = regexp.MustCompile(`\d{14}-[0-9a-f]{12}`)

// cliproxyVersion is the CLIProxyAPI module version from the binary's build info.
func cliproxyVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == cliproxyModule && dep.Version != "" {
				return dep.Version
			}
		}
	}

	return unknownVersion
}
