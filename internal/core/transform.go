package core

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
)

func verifySelected(a *archive, mode Mode) error {
	verification, err := verifyArchive(a)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnverifiedInput, err)
	}
	switch mode {
	case ModeV1:
		if !verification.V1Verified {
			return fmt.Errorf("%w: V1 signature", ErrUnverifiedInput)
		}
	case ModeV2:
		hasV2, hasV3 := archiveModernPairs(a)
		if hasPairID(a, apksigblock.IDV31Signature) && !verification.V31Verified {
			return fmt.Errorf("%w: V3.1 signature", ErrUnverifiedInput)
		}
		if hasPairID(a, apksigblock.IDV3Signature) && !verification.V3Verified {
			return fmt.Errorf("%w: V3 signature", ErrUnverifiedInput)
		}
		if !hasV3 && hasV2 && !verification.V2Verified {
			return fmt.Errorf("%w: V2 signature", ErrUnverifiedInput)
		}
		if !hasV2 && !hasV3 {
			return fmt.Errorf("%w: no V2/V3 signature pair", ErrUnverifiedInput)
		}
	default:
		return ErrInvalidMode
	}
	return nil
}

func hasPairID(a *archive, id uint32) bool {
	if a == nil || a.block == nil {
		return false
	}
	for _, pair := range a.block.Pairs {
		if pair.ID == id {
			return true
		}
	}
	return false
}

// Pack adds channel metadata to an APK and writes the result to w. The input
// ReaderAt is never modified. Set VerifyInput to verify the selected signing
// scheme before writing; structural checks always run.
func Pack(r io.ReaderAt, size int64, channel string, w io.Writer, opts TransformOptions) error {
	if w == nil {
		return errors.New("apktag: nil Writer")
	}
	if err := ValidateBlockID(opts.BlockID); err != nil {
		return err
	}
	a, err := loadArchive(r, size)
	if err != nil {
		return err
	}
	mode, err := selectedMode(a, opts.Mode)
	if err != nil {
		return err
	}
	if opts.VerifyInput {
		if err := verifySelected(a, mode); err != nil {
			return err
		}
	}
	logger := CurrentLogger(opts.Logger)
	apkPath := opts.ApkPath
	if apkPath == "" {
		apkPath = readerPath(r)
	}
	if apkPath != "" {
		if abs, err := filepath.Abs(apkPath); err == nil {
			apkPath = abs
		}
	}
	destPath := opts.DestPath
	if destPath != "" {
		if abs, err := filepath.Abs(destPath); err == nil {
			destPath = abs
		}
	}
	var output []byte
	switch mode {
	case ModeV1:
		output, err = writeV1(a, channel, logger, apkPath)
	case ModeV2:
		output, err = writeV2(a, channel, opts.BlockID, logger, destPath)
	default:
		err = ErrInvalidMode
	}
	if err != nil {
		return err
	}
	return writeOutput(w, output)
}

// RemoveChannel removes channel metadata according to opts. Auto mode removes
// both V2/V3 and V1 metadata when both are present; explicit modes only touch
// their selected representation.
func RemoveChannel(r io.ReaderAt, size int64, w io.Writer, opts TransformOptions) error {
	if w == nil {
		return errors.New("apktag: nil Writer")
	}
	if err := ValidateBlockID(opts.BlockID); err != nil {
		return err
	}
	a, err := loadArchive(r, size)
	if err != nil {
		return err
	}
	logger := CurrentLogger(opts.Logger)
	if logger != nil && opts.VerifyInput {
		LogPrintln(logger, "start check apk signature mode...")
		verification, _ := verifyArchive(a)
		v1Verified := verification != nil && verification.V1Verified
		v2Verified := verification != nil && verification.V2Verified
		v3Verified := verification != nil && (verification.V3Verified || verification.V31Verified)
		LogPrintf(logger, "Verified using v1 scheme (JAR signing): %t\n", v1Verified)
		LogPrintf(logger, "Verified using v2 scheme (APK Signature Scheme v2): %t\n", v2Verified)
		LogPrintf(logger, "Verified using v3 scheme (APK Signature Scheme v3): %t\n", v3Verified)
	}
	apkPath := opts.ApkPath
	if apkPath == "" {
		apkPath = readerPath(r)
	}
	if apkPath != "" {
		if abs, err := filepath.Abs(apkPath); err == nil {
			apkPath = abs
		}
	}
	destPath := opts.DestPath
	if destPath == "" {
		destPath = apkPath
	}
	if destPath != "" {
		if abs, err := filepath.Abs(destPath); err == nil {
			destPath = abs
		}
	}
	baseName := filepath.Base(apkPath)
	if a.block != nil && logger != nil {
		LogPrintf(logger, "baseApk : %s\nApkSectionInfo = %s\n", apkPath, FormatApkSectionInfo(size, true, 0, int(a.block.CDOffset-a.block.StartOffset), int(a.eocd.CDSize), len(a.eocd.Bytes), a.block.StartOffset, a.eocd.CDStartOffset, a.eocd.Offset))
	}
	requested, err := normalizeMode(opts.Mode)
	if err != nil {
		return err
	}
	mode, err := selectedMode(a, requested)
	if err != nil {
		return err
	}
	if opts.VerifyInput {
		if err := verifySelected(a, mode); err != nil {
			return err
		}
	}
	if requested != ModeAuto {
		var output []byte
		if mode == ModeV1 {
			output, err = removeV1(a, logger, baseName)
		} else {
			output, err = removeV2(a, opts.BlockID, logger, destPath)
		}
		if err != nil {
			return err
		}
		return writeOutput(w, output)
	}

	hasV2, hasV3 := archiveModernPairs(a)
	hasModern := hasV2 || hasV3
	_, v1Found, v1Err := parseV1Comment(v1Comment(a))
	if v1Err != nil {
		return v1Err
	}
	_, v2Found, pairErr := channelPair(a.block, normalizeBlockID(opts.BlockID))
	if pairErr != nil {
		return pairErr
	}
	if !v2Found && !v1Found {
		if logger != nil && a.block != nil {
			LogPrintf(logger, "removeIdValue , existed IdValueMap = %s\n", FormatIdValueMap(a.block.Pairs))
			LogPrintln(logger, "removeIdValue , No idValue was deleted")
		}
		return ErrChannelNotFound
	}
	output := a.data
	if hasModern && v2Found {
		output, err = removeV2(a, opts.BlockID, logger, destPath)
		if err != nil {
			return err
		}
	}
	if v1Found {
		if hasModern {
			next, loadErr := loadArchive(bytes.NewReader(output), int64(len(output)))
			if loadErr != nil {
				return loadErr
			}
			output, err = removeV1(next, logger, baseName)
		} else {
			output, err = removeV1(a, logger, baseName)
		}
		if err != nil {
			return err
		}
	}
	return writeOutput(w, output)
}
