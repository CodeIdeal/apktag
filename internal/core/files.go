package core

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode"

	"github.com/CodeIdeal/apktag/internal/logging"
)

// PackFiles creates one independent artifact per channel. The base APK is
// loaded once and is never modified. Results retain the input channel order.
func PackFiles(basePath string, channels []string, opts BatchOptions) (artifacts []Artifact, err error) {
	op := logging.Start("pack_files", "base_path", basePath, "block_id", normalizeBlockID(opts.BlockID))
	var errorReported bool
	defer func() {
		if errorReported {
			op.FinishReported(err)
		} else {
			op.Finish(err)
		}
	}()
	op.Step("validate_options")
	if err := ValidateBlockID(opts.BlockID); err != nil {
		return nil, err
	}
	if basePath == "" {
		return nil, errors.New("apktag: base APK path is empty")
	}
	op.Step("read_base")
	baseData, err := os.ReadFile(basePath)
	if err != nil {
		return nil, fmt.Errorf("apktag: read base APK: %w", err)
	}
	op.Info("base APK read", "bytes", len(baseData))
	op.Step("normalize_channels")
	normalized, err := normalizeChannels(channels)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return nil, errors.New("apktag: no channels supplied")
	}
	op.Info("channels normalized", "input_count", len(channels), "channel_count", len(normalized))
	op.Step("prepare_paths")
	baseName := filepath.Base(basePath)
	if strings.EqualFold(filepath.Ext(baseName), ".apk") {
		baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))
	}
	outputDir := opts.OutputDir
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("apktag: create output directory: %w", err)
	}
	pattern := opts.OutputPattern
	if pattern == "" {
		pattern = "{channel}-{base}.apk"
	}
	if filepath.IsAbs(pattern) {
		return nil, errors.New("apktag: output pattern must be relative")
	}
	paths := make([]string, len(normalized))
	seenPaths := make(map[string]struct{}, len(paths))
	absoluteBase, _ := filepath.Abs(basePath)
	for i, channel := range normalized {
		name := strings.NewReplacer("{channel}", channel, "{base}", baseName).Replace(pattern)
		if name == "" || filepath.IsAbs(name) {
			return nil, errors.New("apktag: output pattern generated an invalid path")
		}
		clean := filepath.Clean(filepath.Join(outputDir, name))
		if !withinDir(outputDir, clean) {
			return nil, fmt.Errorf("apktag: output path escapes output directory: %s", clean)
		}
		absolutePath, _ := filepath.Abs(clean)
		if absoluteBase != "" && absolutePath == absoluteBase {
			return nil, errors.New("apktag: output path must differ from base APK")
		}
		if _, exists := seenPaths[clean]; exists {
			return nil, fmt.Errorf("apktag: output pattern collision at %s", clean)
		}
		seenPaths[clean] = struct{}{}
		if !opts.Overwrite {
			if _, statErr := os.Stat(clean); statErr == nil {
				return nil, fmt.Errorf("apktag: output exists: %s", clean)
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return nil, fmt.Errorf("apktag: inspect output %s: %w", clean, statErr)
			}
		}
		paths[i] = clean
	}

	baseArchive, err := loadArchiveWithLog(bytes.NewReader(baseData), int64(len(baseData)), op)
	if err != nil {
		return nil, err
	}
	mode, err := selectedMode(baseArchive, opts.Mode)
	if err != nil {
		return nil, err
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers > len(normalized) {
		workers = len(normalized)
	}
	op.Step("process_channels")
	op.Info("batch workers started", "workers", workers, "channel_count", len(normalized))
	type result struct {
		index    int
		artifact Artifact
		err      error
	}
	jobs := make(chan int)
	results := make(chan result, len(normalized))
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				child := op.Child("pack_channel", "channel", normalized[index], "path", paths[index])
				var buffer bytes.Buffer
				channelErr := pack(bytes.NewReader(baseData), int64(len(baseData)), normalized[index], &buffer, opts.TransformOptions, child)
				if channelErr == nil {
					channelErr = atomicWrite(paths[index], buffer.Bytes(), opts.Overwrite, child)
				}
				child.Finish(channelErr)
				if channelErr != nil {
					results <- result{index: index, err: fmt.Errorf("channel %q: %w", normalized[index], channelErr)}
					continue
				}
				results <- result{index: index, artifact: Artifact{Channel: normalized[index], Path: paths[index], Mode: mode}}
			}
		}()
	}
	go func() {
		for index := range normalized {
			jobs <- index
		}
		close(jobs)
		group.Wait()
		close(results)
	}()
	artifacts = make([]Artifact, len(normalized))
	succeeded, failed := 0, 0
	var firstErr error
	for item := range results {
		if item.err != nil {
			failed++
			if firstErr == nil {
				firstErr = item.err
			}
			continue
		}
		succeeded++
		artifacts[item.index] = item.artifact
	}
	op.Info("batch finished", "succeeded", succeeded, "failed", failed, "total", len(normalized))
	if firstErr != nil {
		errorReported = true
		return nil, firstErr
	}
	return artifacts, nil
}

func withinDir(dir, path string) bool {
	absDir, errDir := filepath.Abs(dir)
	absPath, errPath := filepath.Abs(path)
	if errDir != nil || errPath != nil {
		return false
	}
	rel, err := filepath.Rel(absDir, absPath)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func normalizeChannels(channels []string) ([]string, error) {
	result := make([]string, 0, len(channels))
	seen := make(map[string]struct{}, len(channels))
	for _, raw := range channels {
		channel := strings.TrimSpace(raw)
		channel = strings.TrimSpace(strings.TrimPrefix(channel, "\ufeff"))
		if channel == "" {
			continue
		}
		if err := validateChannelName(channel); err != nil {
			return nil, err
		}
		if _, exists := seen[channel]; exists {
			continue
		}
		seen[channel] = struct{}{}
		result = append(result, channel)
	}
	return result, nil
}

func validateChannelName(channel string) error {
	if channel == "" {
		return ErrInvalidChannel
	}
	for _, r := range channel {
		if r == '/' || r == '\\' || r == 0 || unicode.IsControl(r) {
			return fmt.Errorf("%w: %q contains a path separator or control character", ErrInvalidChannel, channel)
		}
	}
	return nil
}

func atomicWrite(path string, data []byte, overwrite bool, op *logging.Operation) error {
	op.Step("create_temporary_file")
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".apktag-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			cleanupErr := os.Remove(temporaryName)
			op.Debug("temporary file cleanup", "temporary_path", temporaryName, "error", cleanupErr)
		}
	}()
	op.Step("write_temporary_file")
	if err := writeOutput(temporary, data); err != nil {
		return err
	}
	op.Step("chmod_temporary_file")
	if err := temporary.Chmod(0o644); err != nil {
		return err
	}
	op.Step("sync_temporary_file")
	if err := temporary.Sync(); err != nil {
		return err
	}
	op.Step("close_temporary_file")
	if err := temporary.Close(); err != nil {
		return err
	}
	op.Step("check_overwrite")
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("output exists: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	op.Step("rename_output")
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	keep = true
	op.Info("output committed", "path", path, "bytes", len(data), "status", "completed")
	return nil
}

func readChannelFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return normalizeChannels(strings.Split(string(data), "\n"))
}
