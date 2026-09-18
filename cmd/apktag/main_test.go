package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apktag "github.com/CodeIdeal/apktag"
)

func makeCLIAPK(t *testing.T, path string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("cli fixture")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func captureRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	runErr := run(args)
	if closeErr := writer.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	os.Stdout = oldStdout
	data, readErr := io.ReadAll(reader)
	if closeErr := reader.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(data), runErr
}

func TestCLIPutGetRemoveWorkflow(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.apk")
	base := makeCLIAPK(t, basePath)
	channelsPath := filepath.Join(dir, "channels.txt")
	if err := os.WriteFile(channelsPath, []byte("\ufeff one\n\n two \none\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dist := filepath.Join(dir, "dist")
	output, err := captureRun(t, "put", "-c", channelsPath, "--mode", "v1", "--out", dist, "--workers", "1", "--no-verify", basePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, filepath.Join(dist, "one-base.apk")) || !strings.Contains(output, filepath.Join(dist, "two-base.apk")) {
		t.Fatalf("put output = %q", output)
	}
	positionalDist := filepath.Join(dir, "positional-dist")
	if _, err := captureRun(t, "put", "-c", "three", "--mode", "v1", "--no-verify", basePath, positionalDist); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(positionalDist, "three-base.apk")); err != nil {
		t.Fatalf("positional output directory was ignored: %v", err)
	}
	for _, channel := range []string{"one", "two"} {
		path := filepath.Join(dist, channel+"-base.apk")
		getOutput, getErr := captureRun(t, "get", "-c", path)
		wantChannel := fmt.Sprintf("Channel: %s,len=%d", channel, len(channel))
		if getErr != nil || !strings.Contains(getOutput, wantChannel) {
			t.Fatalf("get %s = %q, want channel line %q, err: %v", channel, getOutput, wantChannel, getErr)
		}
	}
	status, err := captureRun(t, "get", "-s", filepath.Join(dist, "one-base.apk"))
	if err != nil || !strings.Contains(status, "signature mode:") || !strings.Contains(status, "Verified using v1 scheme") {
		t.Fatalf("status = %q, %v", status, err)
	}
	cleaned := filepath.Join(dir, "cleaned.apk")
	removeOutput, err := captureRun(t, "remove", "-c", filepath.Join(dist, "one-base.apk"), "--no-verify", cleaned)
	if err != nil || !strings.Contains(removeOutput, "remove channel success") {
		t.Fatalf("remove output = %q, %v", removeOutput, err)
	}
	cleanedData, err := os.ReadFile(cleaned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apktag.ReadChannel(bytes.NewReader(cleanedData), int64(len(cleanedData))); err == nil {
		t.Fatal("removed CLI artifact still contains a channel")
	}
	if got, err := os.ReadFile(basePath); err != nil || !bytes.Equal(got, base) {
		t.Fatalf("base changed: %v", err)
	}
}

func TestCLISingleOutputOverwriteAndFailures(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.apk")
	makeCLIAPK(t, basePath)
	outputPath := filepath.Join(dir, "single.apk")
	if _, err := captureRun(t, "put", "-c", "single", "--mode", "v1", "--no-verify", "--out", outputPath, basePath); err != nil {
		t.Fatal(err)
	}
	if _, err := captureRun(t, "put", "-c", "single", "--mode", "v1", "--no-verify", "--out", outputPath, basePath); err == nil {
		t.Fatal("existing single output was overwritten without --overwrite")
	}
	if _, err := captureRun(t, "put", "-c", "single", "--mode", "v1", "--no-verify", "--overwrite", "--out", outputPath, basePath); err != nil {
		t.Fatal(err)
	}
	if _, err := captureRun(t, "get"); err == nil {
		t.Fatal("get without an APK path succeeded")
	}
	if _, err := captureRun(t, "get", "-c", basePath); err == nil {
		t.Fatal("get on APK without channel succeeded, want error")
	}
	corruptPath := filepath.Join(dir, "corrupt.apk")
	if err := os.WriteFile(corruptPath, []byte("not a zip file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := captureRun(t, "get", "-s", corruptPath); err == nil {
		t.Fatal("get -s on corrupt APK succeeded, want error")
	}
	inPlaceApk := filepath.Join(dir, "inplace.apk")
	if _, err := captureRun(t, "put", "-c", "inplace_chan", "--mode", "v1", "--no-verify", "--overwrite", "--out", inPlaceApk, basePath); err != nil {
		t.Fatal(err)
	}
	if _, err := captureRun(t, "remove", "-c", inPlaceApk, "--no-verify"); err != nil {
		t.Fatalf("in-place remove failed: %v", err)
	}
	if _, err := captureRun(t, "remove", "--mode", "invalid", outputPath); err == nil {
		t.Fatal("invalid remove mode succeeded")
	}
	if _, err := captureRun(t, "put", "-c", "single", "--mode", "v1", "--no-verify", filepath.Join(dir, "missing.apk"), dir); err == nil {
		t.Fatal("missing base APK succeeded")
	}
	if _, err := captureRun(t, "put", "-c", "single", "--mode", "v1", "--no-verify", basePath, dir, "extra"); err == nil {
		t.Fatal("extra put argument was ignored")
	}
	if _, err := captureRun(t, "get", outputPath, "extra"); err == nil {
		t.Fatal("extra get argument was ignored")
	}
	if _, err := captureRun(t, "remove", "-c", outputPath, "--no-verify", filepath.Join(dir, "cleaned-1.apk"), filepath.Join(dir, "cleaned-2.apk")); err == nil {
		t.Fatal("extra remove argument was ignored")
	}
}

func TestCLIHelp(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"put", "-h"}, {"get", "-h"}, {"remove", "-h"}} {
		if _, err := captureRun(t, args...); err != nil {
			t.Fatalf("%v help: %v", args, err)
		}
	}
}

func TestParseBlockID(t *testing.T) {
	tests := map[string]uint32{"VasDolly": apktag.ChannelPairID, "walle": apktag.WallePairID, "0x881155FF": apktag.ChannelPairID}
	for input, want := range tests {
		got, err := parseBlockID(input)
		if err != nil || got != want {
			t.Errorf("parseBlockID(%q) = %#x, %v", input, got, err)
		}
	}
	for _, input := range []string{"0", "71777777", "881155FF", "881155"} {
		if _, err := parseBlockID(input); err == nil {
			t.Errorf("unprefixed block ID %q accepted", input)
		}
	}
	for _, input := range []string{
		"0x42726577",
		"0x7109871a",
		"0xf05368c0",
		"0x1b93ad61",
		"0x2b09189e",
		"0x6dff800d",
		"0x504b4453",
	} {
		if _, err := parseBlockID(input); !errors.Is(err, apktag.ErrReservedBlockID) {
			t.Errorf("parseBlockID(%q) error = %v, want ErrReservedBlockID", input, err)
		}
	}
}
