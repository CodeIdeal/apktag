// Package logging owns the process-wide logger and operation-scoped stage logs.
package logging

import (
	"context"
	"log/slog"
	"runtime"
	"sync/atomic"
	"time"
)

var configured atomic.Pointer[slog.Logger]

// SetLogger changes the logger for future operations. Nil uses slog.Default.
func SetLogger(logger *slog.Logger) { configured.Store(logger) }

// Logger returns the current logger without changing the host's slog default.
func Logger() *slog.Logger {
	if logger := configured.Load(); logger != nil {
		return logger
	}
	return slog.Default()
}

// Operation belongs to one goroutine. Child operations share the logger snapshot.
type Operation struct {
	logger       *slog.Logger
	base         *slog.Logger
	started      time.Time
	stage        string
	stageStarted time.Time
}

func Start(name string, attrs ...any) *Operation { return newOperation(Logger(), name, attrs...) }
func New(logger *slog.Logger, name string, attrs ...any) *Operation {
	return newOperation(logger, name, attrs...)
}
func newOperation(logger *slog.Logger, name string, attrs ...any) *Operation {
	base := logger.With(attrs...)
	o := &Operation{base: base, logger: base.With("operation", name), started: time.Now()}
	o.log(4, slog.LevelInfo, "operation started", "status", "started")
	return o
}
func (o *Operation) Child(name string, attrs ...any) *Operation {
	return newOperation(o.base, name, attrs...)
}
func (o *Operation) Info(message string, attrs ...any) {
	o.log(3, slog.LevelInfo, message, attrs...)
}
func (o *Operation) Debug(message string, attrs ...any) {
	o.log(3, slog.LevelDebug, message, attrs...)
}
func (o *Operation) Warn(message string, attrs ...any) {
	o.log(3, slog.LevelWarn, message, attrs...)
}

// skip counts frames from runtime.Callers, including this method and its wrapper.
func (o *Operation) log(skip int, level slog.Level, message string, attrs ...any) {
	if o == nil {
		return
	}
	ctx := context.Background()
	if !o.logger.Enabled(ctx, level) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(skip, pcs[:])
	record := slog.NewRecord(time.Now(), level, message, pcs[0])
	record.Add("stage", o.stage)
	record.Add(attrs...)
	_ = o.logger.Handler().Handle(ctx, record)
}

func (o *Operation) endStage(err error, skip int) {
	if o == nil || o.stage == "" {
		return
	}
	status := "completed"
	attrs := []any{"duration", time.Since(o.stageStarted)}
	if err != nil {
		status = "failed"
		attrs = append(attrs, "error", err)
	}
	o.log(skip+1, slog.LevelDebug, "stage finished", append(attrs, "status", status)...)
}

// Step finishes the previous stage and starts the next. Failures are reported by Finish.
func (o *Operation) Step(stage string) {
	if o == nil {
		return
	}
	o.endStage(nil, 3)
	o.stage, o.stageStarted = stage, time.Now()
	o.log(3, slog.LevelDebug, "stage started", "status", "started")
}
func (o *Operation) Finish(err error) {
	o.finish(err, false)
}

// FinishReported records a summary when a nested operation already logged the
// error. The original error remains unchanged for the caller.
func (o *Operation) FinishReported(err error) {
	o.finish(err, true)
}

func (o *Operation) finish(err error, reported bool) {
	if o == nil {
		return
	}
	o.endStage(err, 4)
	attrs := []any{"duration", time.Since(o.started)}
	if err != nil {
		if reported {
			o.log(4, slog.LevelInfo, "operation failed", append(attrs, "status", "failed", "error_reported", true)...)
		} else {
			o.log(4, slog.LevelError, "operation failed", append(attrs, "status", "failed", "error", err)...)
		}
		return
	}
	o.log(4, slog.LevelInfo, "operation completed", append(attrs, "status", "completed")...)
}
