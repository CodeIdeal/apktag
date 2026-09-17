package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/CodeIdeal/apktag/internal/logging"
)

// JSONHandler serializes concurrent Handle calls. Decode only after workers finish.
func captureLogs(t *testing.T, level slog.Level) (*bytes.Buffer, *slog.Logger) {
	t.Helper()
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: level})).With("component", "test")
	logging.SetLogger(logger)
	t.Cleanup(func() { logging.SetLogger(nil) })
	return &output, logger
}
func records(t *testing.T, output *bytes.Buffer) []map[string]any {
	t.Helper()
	var result []map[string]any
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for {
		var record map[string]any
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, record)
	}
	return result
}
func requireRecord(t *testing.T, output *bytes.Buffer, fields map[string]any) {
	t.Helper()
	for _, record := range records(t, output) {
		matches := true
		for key, value := range fields {
			if record[key] != value {
				matches = false
				break
			}
		}
		if matches {
			return
		}
	}
	t.Fatalf("missing log %v in\n%s", fields, output.String())
}

func TestLoggingStagesAndErrors(t *testing.T) {
	for _, mode := range []Mode{ModeV1, ModeV2} {
		t.Run(string(mode), func(t *testing.T) {
			output, _ := captureLogs(t, slog.LevelDebug)
			input := makeV1SignedAPK(t)
			if mode == ModeV2 {
				input = makeModernSignedAPK(t, false, false)
			}
			var packed, removed bytes.Buffer
			opts := TransformOptions{Mode: mode, VerifyInput: true}
			if err := Pack(bytes.NewReader(input), int64(len(input)), "store", &packed, opts); err != nil {
				t.Fatal(err)
			}
			channel, err := ReadChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()))
			if err != nil || channel != "store" {
				t.Fatalf("read: %q %v", channel, err)
			}
			if err := RemoveChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()), &removed, opts); err != nil {
				t.Fatal(err)
			}
			for _, stage := range []string{"eocd", "central_directory", "signing_block", "verify_signature", "write_" + string(mode) + "_channel", "remove_" + string(mode) + "_channel", "write_output"} {
				requireRecord(t, output, map[string]any{"stage": stage, "msg": "stage finished", "status": "completed"})
			}
			requireRecord(t, output, map[string]any{"msg": "selected signature verified", "verified": true})
			if mode == ModeV1 {
				requireRecord(t, output, map[string]any{"msg": "falling back to V1 channel"})
			}
			for _, record := range records(t, output) {
				if record["component"] != "test" {
					t.Fatal("injected attributes lost")
				}
			}
		})
	}
	for _, tc := range []struct {
		name  string
		stage string
		run   func() error
	}{
		{"malformed", "archive_input", func() error { return Pack(bytes.NewReader(nil), 0, "x", io.Discard, TransformOptions{}) }},
		{"writer", "write_output", func() error {
			input := makeZIP(t, "")
			return Pack(bytes.NewReader(input), int64(len(input)), "x", failingWriter{}, TransformOptions{})
		}},
		{"verification", "verify_signature", func() error {
			input := makeZIP(t, "")
			return Pack(bytes.NewReader(input), int64(len(input)), "x", io.Discard, TransformOptions{VerifyInput: true})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, _ := captureLogs(t, slog.LevelDebug)
			if err := tc.run(); err == nil {
				t.Fatal("expected failure")
			}
			count := 0
			for _, record := range records(t, output) {
				if record["level"] == "ERROR" {
					count++
					if record["stage"] != tc.stage || record["error"] == nil {
						t.Fatalf("bad failure: %v", record)
					}
				}
				if record["msg"] == "operation completed" {
					t.Fatal("failed operation reported success")
				}
			}
			if count != 1 {
				t.Fatalf("error logged %d times", count)
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write rejected") }

func TestLoggingWarningsSkipAndLevel(t *testing.T) {
	output, _ := captureLogs(t, slog.LevelDebug)
	input := makeZIP(t, "")
	detection, err := Detect(bytes.NewReader(input), int64(len(input)))
	if err != nil {
		t.Fatal(err)
	}
	if detection.Verified || len(detection.Warnings) == 0 {
		t.Fatalf("unexpected detection: %+v", detection)
	}
	requireRecord(t, output, map[string]any{"level": "WARN"})
	requireRecord(t, output, map[string]any{"msg": "signature verification result", "verified": false})
	if err := Pack(bytes.NewReader(input), int64(len(input)), "store", io.Discard, TransformOptions{}); err != nil {
		t.Fatal(err)
	}
	requireRecord(t, output, map[string]any{"msg": "signature verification skipped", "status": "skipped"})
	filtered, _ := captureLogs(t, slog.LevelError)
	if err := Pack(bytes.NewReader(input), int64(len(input)), "store", io.Discard, TransformOptions{}); err != nil {
		t.Fatal(err)
	}
	if filtered.Len() != 0 {
		t.Fatalf("filtered logs: %s", filtered)
	}
}

func TestLoggingBatchPartialFailure(t *testing.T) {
	output, _ := captureLogs(t, slog.LevelDebug)
	dir := t.TempDir()
	base := filepath.Join(dir, "base.apk")
	original := makeZIP(t, "")
	if err := os.WriteFile(base, original, 0600); err != nil {
		t.Fatal(err)
	}
	// A directory at the destination forces one rename failure after transformation.
	if err := os.Mkdir(filepath.Join(dir, "bad-base.apk"), 0700); err != nil {
		t.Fatal(err)
	}
	artifacts, err := PackFiles(base, []string{"good", "bad"}, BatchOptions{OutputDir: dir, Workers: 2, Overwrite: true})
	if err == nil || artifacts != nil {
		t.Fatalf("partial failure: %v %v", artifacts, err)
	}
	requireRecord(t, output, map[string]any{"msg": "batch finished", "succeeded": float64(1), "failed": float64(1), "total": float64(2)})
	requireRecord(t, output, map[string]any{"msg": "output committed", "channel": "good"})
	requireRecord(t, output, map[string]any{"msg": "operation failed", "channel": "bad", "stage": "rename_output"})
	requireRecord(t, output, map[string]any{"msg": "temporary file cleanup", "channel": "bad"})
	for _, record := range records(t, output) {
		if record["msg"] == "output committed" && record["channel"] == "bad" {
			t.Fatal("failed output reported committed")
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "good-base.apk")); err != nil {
		t.Fatal(err)
	}
	if current, err := os.ReadFile(base); err != nil || !bytes.Equal(current, original) {
		t.Fatal("base changed")
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".apktag-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary files leaked: %v %v", leftovers, err)
	}
}

type pausedReader struct {
	io.ReaderAt
	once    sync.Once
	entered chan struct{}
	resume  chan struct{}
}

func (r *pausedReader) ReadAt(p []byte, off int64) (int, error) {
	r.once.Do(func() { close(r.entered); <-r.resume })
	return r.ReaderAt.ReadAt(p, off)
}
func TestLoggingSnapshotAndConcurrentReplacement(t *testing.T) {
	oldOutput, oldLogger := captureLogs(t, slog.LevelInfo)
	var newOutput bytes.Buffer
	newLogger := slog.New(slog.NewJSONHandler(&newOutput, nil))
	input := makeZIP(t, "")
	reader := &pausedReader{ReaderAt: bytes.NewReader(input), entered: make(chan struct{}), resume: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- Pack(reader, int64(len(input)), "old", io.Discard, TransformOptions{}) }()
	<-reader.entered
	logging.SetLogger(newLogger)
	close(reader.resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if newOutput.Len() != 0 {
		t.Fatal("in-flight operation changed logger")
	}
	requireRecord(t, oldOutput, map[string]any{"msg": "operation completed", "channel": "old"})
	if err := Pack(bytes.NewReader(input), int64(len(input)), "new", io.Discard, TransformOptions{}); err != nil {
		t.Fatal(err)
	}
	requireRecord(t, &newOutput, map[string]any{"msg": "operation completed", "channel": "new"})
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		for i := 0; i < 100; i++ {
			logging.SetLogger(oldLogger)
			logging.SetLogger(newLogger)
		}
	}()
	go func() {
		defer group.Done()
		for i := 0; i < 30; i++ {
			if err := Pack(bytes.NewReader(input), int64(len(input)), "race", io.Discard, TransformOptions{}); err != nil {
				t.Error(err)
			}
		}
	}()
	group.Wait()
}

// The hook changes the global logger as soon as the batch operation starts.
type switchHandler struct {
	slog.Handler
	once *sync.Once
	next *slog.Logger
}

func (h switchHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "operation started" {
		h.once.Do(func() { logging.SetLogger(h.next) })
	}
	return h.Handler.Handle(ctx, r)
}
func (h switchHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return switchHandler{h.Handler.WithAttrs(attrs), h.once, h.next}
}
func (h switchHandler) WithGroup(name string) slog.Handler {
	return switchHandler{h.Handler.WithGroup(name), h.once, h.next}
}
func TestBatchLoggerSnapshot(t *testing.T) {
	var oldOutput, newOutput bytes.Buffer
	next := slog.New(slog.NewJSONHandler(&newOutput, nil))
	// Switch at batch start; all workers must still use the captured logger.
	logger := slog.New(switchHandler{slog.NewJSONHandler(&oldOutput, nil), &sync.Once{}, next})
	logging.SetLogger(logger)
	t.Cleanup(func() { logging.SetLogger(nil) })
	dir := t.TempDir()
	base := filepath.Join(dir, "base.apk")
	if err := os.WriteFile(base, makeZIP(t, ""), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PackFiles(base, []string{"a", "b", "c"}, BatchOptions{OutputDir: dir, Workers: 3}); err != nil {
		t.Fatal(err)
	}
	if newOutput.Len() != 0 {
		t.Fatalf("workers did not inherit snapshot: %s", &newOutput)
	}
	for _, ch := range []string{"a", "b", "c"} {
		requireRecord(t, &oldOutput, map[string]any{"channel": ch, "msg": "output committed"})
	}
	if _, err := ReadChannel(bytes.NewReader(nil), 0); err == nil {
		t.Fatal("expected malformed input")
	}
	if !strings.Contains(newOutput.String(), "operation failed") {
		t.Fatal("new operation did not use replacement")
	}
}
