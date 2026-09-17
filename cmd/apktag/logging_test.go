package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	apktag "github.com/CodeIdeal/apktag"
)

func TestCLIFailureLoggedOnce(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.apk")
	makeCLIAPK(t, base)
	malformed := filepath.Join(dir, "malformed.apk")
	if err := os.WriteFile(malformed, []byte("not an APK"), 0600); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(dir, "bad-base.apk")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, operation string
		args            []string
		sentinel        error
	}{
		{"get", "read_channel", []string{"get", base}, apktag.ErrChannelNotFound},
		{"detect", "detect", []string{"get", "-s", malformed}, nil},
		{"remove", "remove", []string{"remove", "--no-verify", base}, apktag.ErrChannelNotFound},
		{"put input", "pack_files", []string{"put", "-c", "store", "--out", dir, malformed}, nil},
		{"put worker", "pack_channel", []string{"put", "-c", "good,bad", "--no-verify", "--overwrite", "--out", dir, base}, nil},
		{"CLI arguments", "cli_get", []string{"get"}, nil},
		{"CLI open", "cli_get", []string{"get", filepath.Join(dir, "missing.apk")}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, logs, err := captureCommand(t, tc.args...)
			if err == nil || out != "" {
				t.Fatalf("unexpected result: %q %v", out, err)
			}
			if tc.sentinel != nil && !errors.Is(err, tc.sentinel) {
				t.Fatalf("error changed: %v", err)
			}
			if strings.Count(logs, "level=ERROR") != 1 {
				t.Fatalf("expected one error:\n%s", logs)
			}
			for _, line := range strings.Split(logs, "\n") {
				if strings.Contains(line, "level=ERROR") && !strings.Contains(line, "operation="+tc.operation+" ") {
					t.Fatalf("wrong error owner: %s", line)
				}
				if strings.Contains(line, "operation=cli_") && !strings.HasPrefix(tc.operation, "cli_") && strings.Contains(line, "status=failed") {
					if !strings.Contains(line, "error_reported=true") || strings.Contains(line, " error=") {
						t.Fatalf("invalid summary: %s", line)
					}
				}
			}
		})
	}
}

// Files avoid blocking on pipe capacity when Debug emits many stage records.
func captureCommand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	dir := t.TempDir()
	stdout, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdout, stderr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr; apktag.SetLogger(nil) }()
	runErr := run(args)
	if _, err := stdout.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := stderr.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	logs, err := io.ReadAll(stderr)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), string(logs), runErr
}

func TestCLILogLevelsAndOutputIsolation(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.apk")
	makeCLIAPK(t, base)
	for _, level := range []string{"", "debug", "info", "warn", "error", "off"} {
		t.Run("level_"+level, func(t *testing.T) {
			path := filepath.Join(dir, "output-"+level+".apk")
			args := []string{"put", "-c", "store", "--no-verify", "--out", path}
			if level != "" {
				args = append(args, "--log-level", level)
			}
			args = append(args, base)
			out, logs, err := captureCommand(t, args...)
			if err != nil {
				t.Fatal(err)
			}
			if out != path+"\n" {
				t.Fatalf("stdout changed: %q", out)
			}
			if level == "" || level == "info" || level == "debug" {
				if !strings.Contains(logs, "level=INFO") || !strings.Contains(logs, "output committed") {
					t.Fatalf("missing Info: %s", logs)
				}
			} else if logs != "" {
				t.Fatalf("logs not filtered: %s", logs)
			}
			if strings.Contains(logs, "level=DEBUG") != (level == "debug") {
				t.Fatalf("Debug filter incorrect: %s", logs)
			}
			getArgs := []string{"get", "--log-level", "info", path}
			out, logs, err = captureCommand(t, getArgs...)
			if err != nil || out != "store\n" || !strings.Contains(logs, "operation completed") {
				t.Fatalf("get: %q %q %v", out, logs, err)
			}
			clean := filepath.Join(dir, "clean-"+level+".apk")
			out, logs, err = captureCommand(t, "remove", "--no-verify", "--log-level", "info", path, clean)
			if err != nil || out != "" || !strings.Contains(logs, "output committed") {
				t.Fatalf("remove: %q %q %v", out, logs, err)
			}
		})
	}
	out, logs, err := captureCommand(t, "get", "-s", base)
	if err != nil || !strings.Contains(out, "verified=false") || !strings.Contains(logs, "level=WARN") {
		t.Fatalf("status warnings: %q %q %v", out, logs, err)
	}
	for _, command := range []string{"put", "get", "remove"} {
		_, logs, err := captureCommand(t, command, "--log-level", "invalid", filepath.Join(dir, "missing.apk"))
		if err == nil || !strings.Contains(err.Error(), "invalid log level") || logs != "" {
			t.Fatalf("invalid level: %q %v", logs, err)
		}
	}
}
func TestCLIChannelFileDebugAndRenameFailure(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.apk")
	makeCLIAPK(t, base)
	channels := filepath.Join(dir, "channels.txt")
	if err := os.WriteFile(channels, []byte("store\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "store.apk")
	_, logs, err := captureCommand(t, "put", "-c", channels, "--no-verify", "--log-level", "debug", "--out", path, base)
	if err != nil || !strings.Contains(logs, "channel file read") {
		t.Fatalf("channel file logs: %q %v", logs, err)
	}
	destination := filepath.Join(dir, "directory")
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	_, logs, err = captureCommand(t, "remove", "--no-verify", "--log-level", "debug", path, destination)
	if err == nil || strings.Count(logs, "level=ERROR") != 1 || !strings.Contains(logs, "stage=rename_output") || !strings.Contains(logs, "temporary file cleanup") || strings.Contains(logs, "output committed") {
		t.Fatalf("rename failure: %q %v", logs, err)
	}
}
func TestDisabledHandlerAllLevels(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(disabledHandler{slog.NewTextHandler(&output, nil)}).With("source", "test").WithGroup("group")
	logger.Log(context.Background(), slog.Level(1000), "must be suppressed")
	if output.Len() != 0 {
		t.Fatal("off allowed custom log level")
	}
}
func TestCLIOffPreservesExitError(t *testing.T) {
	if os.Getenv("APKTAG_TEST_ERROR_PROCESS") == "1" {
		os.Args = []string{"apktag", "get", "--log-level", "off", os.Getenv("APKTAG_TEST_MISSING_PATH")}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIOffPreservesExitError$")
	cmd.Env = append(os.Environ(), "APKTAG_TEST_ERROR_PROCESS=1", "APKTAG_TEST_MISSING_PATH="+filepath.Join(t.TempDir(), "missing.apk"))
	var out, logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &logs
	err := cmd.Run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || out.Len() != 0 || !strings.Contains(logs.String(), "apktag:") || strings.Contains(logs.String(), "level=") {
		t.Fatalf("off error: %q %q %v", &out, &logs, err)
	}
}
