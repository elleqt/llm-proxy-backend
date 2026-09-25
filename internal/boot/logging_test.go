package boot

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An upstream logrus record reaches the process log as a record of its own:
// labelled CLIProxyAPI's with both versions, its fields as attributes, its time
// in UTC. Debug stays off whatever logrus was set to, since it would log request
// details, and upstream's "no request id" placeholder is dropped.
func TestUpstreamLogrusRecordsReachTheProcessLog(t *testing.T) {
	std := logrus.StandardLogger()
	out, formatter, level := std.Out, std.Formatter, std.GetLevel()
	hooks := std.ReplaceHooks(make(logrus.LevelHooks))

	t.Cleanup(func() {
		std.SetOutput(out)
		std.SetFormatter(formatter)
		std.SetLevel(level)
		std.ReplaceHooks(hooks)
	})
	logrus.SetLevel(logrus.DebugLevel)

	var buf bytes.Buffer
	routeLogrus(newLogHandler(&buf, config.LogFormatJSON, "0.1.2"))
	logrus.WithField("body", "secret prompt").Debug("request detail")
	logrus.WithFields(logrus.Fields{"provider": "claude", "request_id": "--------"}).Warn("quota exceeded\n")
	logrus.WithField("request_id", "a1b2c3d4").Info("request served")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2, "want the warning and the info line only")

	var warn, info map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &warn), "record %q", lines[0])
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &info), "record %q", lines[1])

	for k, want := range map[string]any{
		"level": "WARN", "msg": "quota exceeded", "provider": "claude",
		"version": "0.1.2", "component": "cliproxyapi",
	} {
		assert.Equal(t, want, warn[k], "%s (record %s)", k, lines[0])
	}

	version, _ := warn["cliproxy_version"].(string)
	assert.True(t, strings.HasPrefix(version, "v7."),
		"cliproxy_version = %q, want the embedded CLIProxyAPI v7 module's version", version)

	stamp, _ := warn["time"].(string)
	assert.True(t, strings.HasSuffix(stamp, "Z"), "time = %q, want UTC", stamp)
	assert.NotContains(t, warn, "request_id", "the placeholder request_id was kept")
	assert.Equal(t, "a1b2c3d4", info["request_id"], "request_id, want a real id kept")
}

// Trace joins debug and fatal and panic join error; no logrus level lands on a
// less severe slog level than its own.
func TestLogrusLevelsKeepTheirSeverity(t *testing.T) {
	want := map[logrus.Level]slog.Level{
		logrus.TraceLevel: slog.LevelDebug,
		logrus.DebugLevel: slog.LevelDebug,
		logrus.InfoLevel:  slog.LevelInfo,
		logrus.WarnLevel:  slog.LevelWarn,
		logrus.ErrorLevel: slog.LevelError,
		logrus.FatalLevel: slog.LevelError,
		logrus.PanicLevel: slog.LevelError,
	}
	for _, l := range logrus.AllLevels {
		assert.Equal(t, want[l], slogLevel(l), "slogLevel(%v)", l)
	}
}

// The version label prefers what the build injected, then a clean tag go build
// stamped, then the commit the build was made from: a pseudo-version or a dirty
// tree names no release.
func TestVersionPrecedence(t *testing.T) {
	vcs := []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"}}
	for _, tc := range []struct {
		name, injected string
		bi             *debug.BuildInfo
		want           string
	}{
		{"injected wins", "0.1.2", &debug.BuildInfo{Main: debug.Module{Version: "v0.1.1"}, Settings: vcs}, "0.1.2"},
		{"module version", "", &debug.BuildInfo{Main: debug.Module{Version: "v0.1.1"}, Settings: vcs}, "v0.1.1"},
		{"checkout build", "", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: vcs}, "01234567"},
		{"untagged commit", "", &debug.BuildInfo{Main: debug.Module{Version: "v0.1.4-0.20260925101010-0123456789ab"}, Settings: vcs}, "01234567"},
		{"untagged dirty", "", &debug.BuildInfo{Main: debug.Module{Version: "v0.1.4-0.20260925101010-0123456789ab+dirty"}, Settings: vcs}, "01234567"},
		{"dirty tag", "", &debug.BuildInfo{Main: debug.Module{Version: "v0.1.2+dirty"}, Settings: vcs}, "01234567"},
		{"no commit", "", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "unknown"},
		{"no build info", "", nil, "unknown"},
	} {
		assert.Equal(t, tc.want, versionOf(tc.injected, tc.bi), "%s: versionOf", tc.name)
	}
}
