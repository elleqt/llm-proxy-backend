package boot

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/elleqt/llm-proxy-backend/internal/config"
	"github.com/sirupsen/logrus"
)

// Component labels: which code wrote a record.
const (
	componentOwn      = "llmproxy"
	componentUpstream = "cliproxyapi"
)

// newLogHandler is the process log's handler: text or JSON on out
// (LLMPROXY_LOG_FORMAT), timestamps in UTC, and every record labelled with the
// build version. Records carry no component yet; each logger adds its own.
func newLogHandler(out io.Writer, format, version string) slog.Handler {
	opts := &slog.HandlerOptions{ReplaceAttr: utcTime}

	var handler slog.Handler
	if format == config.LogFormatJSON {
		handler = slog.NewJSONHandler(out, opts)
	} else {
		handler = slog.NewTextHandler(out, opts)
	}

	return handler.WithAttrs([]slog.Attr{slog.String("version", version)})
}

// utcTime writes a record's time in UTC, as the process log always has.
func utcTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
		a.Value = slog.TimeValue(a.Value.Time().UTC())
	}

	return a
}

// routeLogrus sends upstream's global logrus into h, labelled as CLIProxyAPI's
// with its module version. logrus then formats and writes nothing itself, and
// stays at info level whatever the environment set before: debug level would log
// request details.
//
// The hook is added, never swapped in: whoever else listens to logrus (the
// end-to-end tests do) keeps listening. Upstream re-points logrus's output only
// through logging.ConfigureLogOutput, which a reload reaches only when
// logging-to-file or logs-max-total-size-mb changes; both are gateway-owned
// settings (app.ownedKeys), so that never happens.
func routeLogrus(h slog.Handler) {
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetOutput(io.Discard)
	logrus.SetFormatter(nopFormatter{})
	logrus.AddHook(logrusBridge{h: h.WithAttrs([]slog.Attr{
		slog.String("component", componentUpstream),
		slog.String("cliproxy_version", cliproxyVersion()),
	})})
}

// logrusBridge forwards upstream CLIProxyAPI's logrus records into slog: the
// message, level and time as they were, every logrus field as an attribute.
type logrusBridge struct{ h slog.Handler }

func (b logrusBridge) Levels() []logrus.Level { return logrus.AllLevels }

func (b logrusBridge) Fire(entry *logrus.Entry) error {
	ctx := entry.Context
	if ctx == nil {
		ctx = context.Background()
	}

	lvl := slogLevel(entry.Level)
	if !b.h.Enabled(ctx, lvl) {
		return nil
	}

	var pc uintptr
	if entry.Caller != nil {
		pc = entry.Caller.PC
	}

	record := slog.NewRecord(entry.Time, lvl, strings.TrimRight(entry.Message, "\r\n"), pc)
	// In key order, as logrus's own formatters write them: lines from one
	// callsite then read and diff alike.
	for _, key := range slices.Sorted(maps.Keys(entry.Data)) {
		v := entry.Data[key]
		if key == "request_id" && v == "--------" {
			continue // upstream's placeholder for "no id"
		}

		record.AddAttrs(slog.Any(key, v))
	}

	if err := b.h.Handle(ctx, record); err != nil {
		return fmt.Errorf("logrus bridge: %w", err)
	}

	return nil
}

// slogLevel maps a logrus level to the nearest slog level: trace joins debug,
// fatal and panic join error.
func slogLevel(l logrus.Level) slog.Level {
	switch l {
	case logrus.TraceLevel, logrus.DebugLevel:
		return slog.LevelDebug
	case logrus.InfoLevel:
		return slog.LevelInfo
	case logrus.WarnLevel:
		return slog.LevelWarn
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		// Error, fatal and panic, like any level logrus may add, map to error below.
	}

	return slog.LevelError
}

// nopFormatter keeps logrus from formatting entries nobody reads: the bridge
// hook is the only consumer, and Out is io.Discard.
type nopFormatter struct{}

func (nopFormatter) Format(*logrus.Entry) ([]byte, error) { return nil, nil }

// processLog is app.InfoLogger over the process's own slog logger. The port
// takes slog.Attr only, so it logs through LogAttrs: *slog.Logger's Warn and Info
// take loose key/value pairs, which the port refuses at compile time.
type processLog struct{ l *slog.Logger }

func (p processLog) Warn(msg string, attrs ...slog.Attr) {
	p.l.LogAttrs(context.Background(), slog.LevelWarn, msg, attrs...)
}

func (p processLog) Info(msg string, attrs ...slog.Attr) {
	p.l.LogAttrs(context.Background(), slog.LevelInfo, msg, attrs...)
}
