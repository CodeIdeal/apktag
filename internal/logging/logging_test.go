package logging_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"runtime"
	"testing"

	"github.com/CodeIdeal/apktag/internal/logging"
)

func TestSourceUsesOperationCallSite(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug}))
	logging.SetLogger(logger)
	t.Cleanup(func() { logging.SetLogger(nil) })
	_, file, _, _ := runtime.Caller(0)
	check := func(line int) {
		t.Helper()
		decoder := json.NewDecoder(&output)
		count := 0
		for {
			var record struct {
				Source struct {
					File string
					Line int
				}
			}
			err := decoder.Decode(&record)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			count++
			if record.Source.File != file || record.Source.Line != line {
				t.Fatalf("source = %s:%d, want %s:%d", record.Source.File, record.Source.Line, file, line)
			}
		}
		if count == 0 {
			t.Fatal("no records emitted")
		}
		output.Reset()
	}
	_, _, line, _ := runtime.Caller(0)
	op := logging.New(logger, "test")
	check(line + 1)
	_, _, line, _ = runtime.Caller(0)
	op.Info("info")
	check(line + 1)
	_, _, line, _ = runtime.Caller(0)
	op.Debug("debug")
	check(line + 1)
	_, _, line, _ = runtime.Caller(0)
	op.Warn("warn")
	check(line + 1)
	_, _, line, _ = runtime.Caller(0)
	op.Step("first")
	check(line + 1)
	_, _, line, _ = runtime.Caller(0)
	op.Step("second")
	check(line + 1)
	_, _, line, _ = runtime.Caller(0)
	op.Finish(errors.New("failed"))
	check(line + 1)
	_, _, line, _ = runtime.Caller(0)
	child := op.Child("child")
	check(line + 1)
	_, _, line, _ = runtime.Caller(0)
	child.Finish(nil)
	check(line + 1)
	_, _, line, _ = runtime.Caller(0)
	parent := logging.Start("parent")
	check(line + 1)
	_, _, line, _ = runtime.Caller(0)
	parent.Step("nested")
	check(line + 1)
	_, _, line, _ = runtime.Caller(0)
	parent.FinishReported(errors.New("already logged"))
	check(line + 1)
}
