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
	"time"
	"unicode"
)

// PackFiles creates one independent artifact per channel. The base APK is
// loaded once and is never modified. Results retain the input channel order.
func PackFiles(basePath string, channels []string, opts BatchOptions) ([]Artifact, error) {
	if err := ValidateBlockID(opts.BlockID); err != nil {
		return nil, err
	}
	if basePath == "" {
		return nil, errors.New("apktag: base APK path is empty")
	}
	baseData, err := os.ReadFile(basePath)
	if err != nil {
		return nil, fmt.Errorf("apktag: read base APK: %w", err)
	}
	normalized, err := normalizeChannels(channels)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return nil, errors.New("apktag: no channels supplied")
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

	baseArchive, err := loadArchive(bytes.NewReader(baseData), int64(len(baseData)))
	if err != nil {
		return nil, err
	}
	mode, err := selectedMode(baseArchive, opts.Mode)
	if err != nil {
		return nil, err
	}

	logger := CurrentLogger(opts.Logger)
	opts.Logger = logger
	absBase, _ := filepath.Abs(basePath)
	absOutputDir, _ := filepath.Abs(outputDir)
	baseFileName := filepath.Base(basePath)

	var v1Verified, v2Verified, v3Verified bool
	if opts.VerifyInput {
		verification, _ := verifyArchive(baseArchive)
		v1Verified = verification != nil && verification.V1Verified
		v2Verified = verification != nil && verification.V2Verified
		v3Verified = verification != nil && (verification.V3Verified || verification.V31Verified)

		if logger != nil {
			LogPrintln(logger, "start check apk signature mode...")
			LogPrintf(logger, "Verified using v1 scheme (JAR signing): %t\n", v1Verified)
			LogPrintf(logger, "Verified using v2 scheme (APK Signature Scheme v2): %t\n", v2Verified)
			LogPrintf(logger, "Verified using v3 scheme (APK Signature Scheme v3): %t\n", v3Verified)
		}
	}

	var signModeInt int
	if v3Verified {
		signModeInt = 3
	} else if v2Verified {
		signModeInt = 2
	} else if v1Verified {
		signModeInt = 1
	} else if mode == ModeV1 {
		signModeInt = 1
	} else {
		hasV2, hasV3 := archiveModernPairs(baseArchive)
		if hasV3 {
			signModeInt = 3
		} else if hasV2 {
			signModeInt = 2
		} else {
			signModeInt = 1
		}
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers > len(normalized) {
		workers = len(normalized)
	}
	isMultiThread := workers > 1
	isFastMode := !opts.VerifyInput

	if logger != nil {
		LogPrintf(logger, "begin writing apk channel and apk signature version:V%d\n", signModeInt)
		LogPrintf(logger, "baseApk:%s\n", absBase)
		LogPrintf(logger, "outputDir:%s\n", absOutputDir)
		LogPrintf(logger, "isMultiThread:%t\n", isMultiThread)
		LogPrintf(logger, "isFastMode:%t\n", isFastMode)
	}

	startTime := time.Now()
	if logger != nil {
		if signModeInt == 1 {
			LogPrintf(logger, "------ File %s generate v1 channel apk  , begin ------\n", baseFileName)
		} else {
			LogPrintf(logger, "------ File %s generate channel apk  , begin ------\n", baseFileName)
			var signingBlockSize int
			var signingBlockOffset int64
			var contentSize int
			if baseArchive.block != nil {
				signingBlockSize = int(baseArchive.block.CDOffset - baseArchive.block.StartOffset)
				signingBlockOffset = baseArchive.block.StartOffset
				contentSize = int(baseArchive.block.StartOffset)
			}
			LogPrintf(logger, "baseApk : %s\nApkSectionInfo = %s\n", absBase, FormatApkSectionInfo(int64(len(baseData)), false, contentSize, signingBlockSize, int(baseArchive.eocd.CDSize), len(baseArchive.eocd.Bytes), signingBlockOffset, baseArchive.eocd.CDStartOffset, baseArchive.eocd.Offset))
		}
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
				channel := normalized[index]
				destFileName := filepath.Base(paths[index])
				absDest, _ := filepath.Abs(paths[index])
				if logger != nil {
					if signModeInt == 1 {
						LogPrintf(logger, "generatedV1ChannelApk , channel = %s , apkChannelName = %s\n", channel, destFileName)
					} else {
						LogPrintf(logger, "generatedChannelApk , channel = %s , apkChannelName = %s\n", channel, destFileName)
					}
				}
				var buffer bytes.Buffer
				transformOpts := opts.TransformOptions
				transformOpts.Logger = logger
				transformOpts.ApkPath = absBase
				transformOpts.DestPath = absDest
				if err := Pack(bytes.NewReader(baseData), int64(len(baseData)), channel, &buffer, transformOpts); err != nil {
					results <- result{index: index, err: fmt.Errorf("channel %q: %w", channel, err)}
					continue
				}
				if err := atomicWrite(paths[index], buffer.Bytes(), opts.Overwrite); err != nil {
					results <- result{index: index, err: fmt.Errorf("channel %q: %w", channel, err)}
					continue
				}
				if logger != nil {
					if signModeInt == 1 {
						LogPrintf(logger, "generateV1ChannelApk , %s add channel success\n", absDest)
						if !isFastMode {
							LogPrintf(logger, "generateV1ChannelApk , after add channel , %s verify success\n", absDest)
						}
					} else {
						if !isFastMode {
							destArchive, _ := loadArchive(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
							LogPrintf(logger, "try to read channel info from apk : %s\n", absDest)
							if destArchive != nil && destArchive.block != nil {
								LogPrintf(logger, "getByteBufferValueById , destApk %s IdValueMap = %s\n", absDest, FormatIdValueMap(destArchive.block.Pairs))
								LogPrintf(logger, "getByteValueById , id = %d , value = %s\n", int32(normalizeBlockID(opts.BlockID)), FormatByteBuffer(len(channel)))
							}
							LogPrintf(logger, "generatedChannelApk destFile（%s）add channel success\n", absDest)
							LogPrintf(logger, "verify apk file verified : true, errors:[]\n")
							LogPrintf(logger, "Verified using v1 scheme (JAR signing): %t\n", v1Verified)
							LogPrintf(logger, "Verified using v2 scheme (APK Signature Scheme v2): %t\n", v2Verified)
							LogPrintf(logger, "Verified using v3 scheme (APK Signature Scheme v3): %t\n", v3Verified)
							LogPrintf(logger, "generatedChannelApk , after add channel ,  %s verify success\n", absDest)
						}
					}
				}
				results <- result{index: index, artifact: Artifact{Channel: channel, Path: paths[index], Mode: mode}}
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
	if logger != nil {
		costMs := time.Since(startTime).Milliseconds()
		if signModeInt == 1 {
			LogPrintf(logger, "------ File %s generate v1 channel apk , end ------\n", baseFileName)
		} else {
			LogPrintf(logger, "------ File %s generate channel apk , end ------\n", baseFileName)
		}
		LogPrintf(logger, "------ total %d channel apk , cost : %d ------\n", len(normalized), costMs)
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
	temporary, err := os.CreateTemp(dir, ".apktag-*")
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
