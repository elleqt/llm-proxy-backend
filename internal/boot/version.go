package boot

import "runtime/debug"

// cliproxyModule is the module path of the embedded CLIProxyAPI.
const cliproxyModule = "github.com/router-for-me/CLIProxyAPI/v7"

// resolveVersion returns the label for logs and llmproxy_build_info: the
// injected build version when set, else the module version, else the VCS
// commit's short sha, else "unknown".
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
		return "unknown"
	}
	// A build from a checkout, rather than go install of a tagged module,
	// reports "(devel)".
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			return s.Value[:min(8, len(s.Value))]
		}
	}
	return "unknown"
}

// cliproxyVersion is the CLIProxyAPI module version from the binary's build info.
func cliproxyVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == cliproxyModule && dep.Version != "" {
				return dep.Version
			}
		}
	}
	return "unknown"
}
