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
)

// PackFiles creates one independent artifact per channel. The base APK is
// loaded once and is never modified. Results retain the input channel order.
func PackFiles(basePath string, channels []string, opts BatchOptions) ([]Artifact, error) {
	if basePath == "" {
		return nil, errors.New("vasdolly: base APK path is empty")
	}
	baseData, err := os.ReadFile(basePath)
	if err != nil {
		return nil, fmt.Errorf("vasdolly: read base APK: %w", err)
	}
	normalized, err := normalizeChannels(channels)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return nil, errors.New("vasdolly: no channels supplied")
	}
	baseName := filepath.Base(basePath)
	if strings.EqualFold(filepath.Ext(baseName), ".apk") {
		baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))
	}
	outputDir := opts.OutputDir
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("vasdolly: create output directory: %w", err)
	}
	pattern := opts.OutputPattern
	if pattern == "" {
		pattern = "{channel}-{base}.apk"
	}
	if filepath.IsAbs(pattern) {
		return nil, errors.New("vasdolly: output pattern must be relative")
	}
	paths := make([]string, len(normalized))
	seenPaths := make(map[string]struct{}, len(paths))
	absoluteBase, _ := filepath.Abs(basePath)
	for i, channel := range normalized {
		name := strings.NewReplacer("{channel}", channel, "{base}", baseName).Replace(pattern)
		if name == "" || filepath.IsAbs(name) {
			return nil, errors.New("vasdolly: output pattern generated an invalid path")
		}
		clean := filepath.Clean(filepath.Join(outputDir, name))
		if !withinDir(outputDir, clean) {
			return nil, fmt.Errorf("vasdolly: output path escapes output directory: %s", clean)
		}
		absolutePath, _ := filepath.Abs(clean)
		if absoluteBase != "" && absolutePath == absoluteBase {
			return nil, errors.New("vasdolly: output path must differ from base APK")
		}
		if _, exists := seenPaths[clean]; exists {
			return nil, fmt.Errorf("vasdolly: output pattern collision at %s", clean)
		}
		seenPaths[clean] = struct{}{}
		if !opts.Overwrite {
			if _, statErr := os.Stat(clean); statErr == nil {
				return nil, fmt.Errorf("vasdolly: output exists: %s", clean)
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return nil, fmt.Errorf("vasdolly: inspect output %s: %w", clean, statErr)
			}
		}
		paths[i] = clean
	}

	baseArchive, err := loadArchive(bytes.NewReader(baseData), int64(len(baseData)))
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
				var buffer bytes.Buffer
				transformOpts := opts.TransformOptions
				if err := Pack(bytes.NewReader(baseData), int64(len(baseData)), normalized[index], &buffer, transformOpts); err != nil {
					results <- result{index: index, err: fmt.Errorf("channel %q: %w", normalized[index], err)}
					continue
				}
				if err := atomicWrite(paths[index], buffer.Bytes(), opts.Overwrite); err != nil {
					results <- result{index: index, err: fmt.Errorf("channel %q: %w", normalized[index], err)}
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
	artifacts := make([]Artifact, len(normalized))
	var firstErr error
	for item := range results {
		if item.err != nil {
			if firstErr == nil {
				firstErr = item.err
			}
			continue
		}
		artifacts[item.index] = item.artifact
	}
	if firstErr != nil {
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

func atomicWrite(path string, data []byte, overwrite bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".vasdolly-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := writeOutput(temporary, data); err != nil {
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("output exists: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	keep = true
	return nil
}

func readChannelFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return normalizeChannels(strings.Split(string(data), "\n"))
}
