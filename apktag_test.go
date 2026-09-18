package apktag_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	apktag "github.com/CodeIdeal/apktag"
)

func TestPublicFacadeV1RoundTrip(t *testing.T) {
	input := makeTestAPK(t)

	var packed bytes.Buffer
	if err := apktag.Pack(bytes.NewReader(input), int64(len(input)), "huawei", &packed, apktag.TransformOptions{Mode: apktag.ModeV1}); err != nil {
		t.Fatal(err)
	}
	channel, err := apktag.ReadChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()))
	if err != nil || channel != "huawei" {
		t.Fatalf("ReadChannel = %q, %v", channel, err)
	}

	var restored bytes.Buffer
	if err := apktag.RemoveChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()), &restored, apktag.TransformOptions{Mode: apktag.ModeV1}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Bytes(), input) {
		t.Fatal("RemoveChannel did not restore the input APK")
	}
	if _, err := apktag.ReadChannel(bytes.NewReader(input), int64(len(input))); !errors.Is(err, apktag.ErrChannelNotFound) {
		t.Fatalf("ReadChannel error = %v, want ErrChannelNotFound", err)
	}
}

func makeTestAPK(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	entry, err := writer.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("test fixture")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

type customMemLogger struct {
	mu   sync.Mutex
	logs []string
}

func (c *customMemLogger) Print(v ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logs = append(c.logs, fmt.Sprint(v...))
}

func (c *customMemLogger) Printf(format string, v ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logs = append(c.logs, fmt.Sprintf(format, v...))
}

func (c *customMemLogger) Println(v ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logs = append(c.logs, fmt.Sprintln(v...))
}

func TestLibraryLoggingDefaultSilent(t *testing.T) {
	apktag.SetLogger(nil)
	input := makeTestAPK(t)

	var packed bytes.Buffer
	if err := apktag.Pack(bytes.NewReader(input), int64(len(input)), "huawei", &packed, apktag.TransformOptions{Mode: apktag.ModeV1}); err != nil {
		t.Fatal(err)
	}
	channel, err := apktag.ReadChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()))
	if err != nil || channel != "huawei" {
		t.Fatalf("ReadChannel = %q, %v", channel, err)
	}
	var restored bytes.Buffer
	if err := apktag.RemoveChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()), &restored, apktag.TransformOptions{Mode: apktag.ModeV1}); err != nil {
		t.Fatal(err)
	}
}

func TestLibraryLoggingSetOutput(t *testing.T) {
	var buf bytes.Buffer
	apktag.SetOutput(&buf)
	defer apktag.SetLogger(nil)

	input := makeTestAPK(t)
	var packed bytes.Buffer
	if err := apktag.Pack(bytes.NewReader(input), int64(len(input)), "huawei", &packed, apktag.TransformOptions{Mode: apktag.ModeV1}); err != nil {
		t.Fatal(err)
	}
	packLog := buf.String()
	if !strings.Contains(packLog, "has no comment") {
		t.Fatalf("packLog missing 'has no comment', got: %s", packLog)
	}

	buf.Reset()
	channel, err := apktag.ReadChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()))
	if err != nil || channel != "huawei" {
		t.Fatalf("ReadChannel = %q, %v", channel, err)
	}
	readLog := buf.String()
	if !strings.Contains(readLog, "try to read channel info from apk") {
		t.Fatalf("readLog missing read channel log, got: %s", readLog)
	}
	if !strings.Contains(readLog, "has comment") {
		t.Fatalf("readLog missing comment log, got: %s", readLog)
	}

	buf.Reset()
	var restored bytes.Buffer
	if err := apktag.RemoveChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()), &restored, apktag.TransformOptions{Mode: apktag.ModeV1}); err != nil {
		t.Fatal(err)
	}
	removeLog := buf.String()
	if !strings.Contains(removeLog, "has comment") {
		t.Fatalf("removeLog missing comment log, got: %s", removeLog)
	}
	if !strings.Contains(removeLog, "remove comment success") {
		t.Fatalf("removeLog missing remove comment success log, got: %s", removeLog)
	}
	if strings.Contains(removeLog, "start check apk signature mode...") {
		t.Fatalf("removeLog should not check signature when VerifyInput is false, got: %s", removeLog)
	}
}

func TestLibraryLoggingCustomLogger(t *testing.T) {
	custom := &customMemLogger{}
	apktag.SetLogger(custom)
	defer apktag.SetLogger(nil)

	input := makeTestAPK(t)
	_, _ = apktag.Detect(bytes.NewReader(input), int64(len(input)))

	allLogs := strings.Join(custom.logs, "")
	if !strings.Contains(allLogs, "start check apk signature mode...") {
		t.Fatalf("custom logger did not receive expected log, got: %s", allLogs)
	}
}

func TestLibraryLoggingPerOperationLogger(t *testing.T) {
	apktag.SetLogger(nil) // global is nil

	input := makeTestAPK(t)
	var packed bytes.Buffer
	opLogger := &customMemLogger{}
	if err := apktag.Pack(bytes.NewReader(input), int64(len(input)), "huawei", &packed, apktag.TransformOptions{
		Mode:   apktag.ModeV1,
		Logger: opLogger,
	}); err != nil {
		t.Fatal(err)
	}
	opLogs := strings.Join(opLogger.logs, "")
	if !strings.Contains(opLogs, "has no comment") {
		t.Fatalf("per-op logger did not receive log, got: %s", opLogs)
	}
}

func TestLibraryLoggingBatchPackFiles(t *testing.T) {
	var buf bytes.Buffer
	apktag.SetOutput(&buf)
	defer apktag.SetLogger(nil)

	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.apk")
	input := makeTestAPK(t)
	if err := os.WriteFile(basePath, input, 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	_, err := apktag.PackFiles(basePath, []string{"testchan"}, apktag.BatchOptions{
		OutputDir: outDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	logs := buf.String()
	if !strings.Contains(logs, "begin writing apk channel and apk signature version:V1") {
		t.Fatalf("batch logs missing header: %s", logs)
	}
	if !strings.Contains(logs, "generatedV1ChannelApk , channel = testchan") {
		t.Fatalf("batch logs missing channel: %s", logs)
	}
	if !strings.Contains(logs, "total 1 channel apk , cost :") {
		t.Fatalf("batch logs missing total summary: %s", logs)
	}
}

func TestLibraryLoggingBatchPackFilesWithEmbeddedLogger(t *testing.T) {
	apktag.SetLogger(nil) // global logger is silent

	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.apk")
	input := makeTestAPK(t)
	if err := os.WriteFile(basePath, input, 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	custom := &customMemLogger{}
	_, err := apktag.PackFiles(basePath, []string{"embedchan"}, apktag.BatchOptions{
		TransformOptions: apktag.TransformOptions{
			Logger: custom,
		},
		OutputDir: outDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	logs := strings.Join(custom.logs, "")
	if !strings.Contains(logs, "generatedV1ChannelApk , channel = embedchan") {
		t.Fatalf("embedded logger in TransformOptions was not honored, logs: %s", logs)
	}
}
