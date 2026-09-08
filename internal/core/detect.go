package core

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

func normalizeMode(mode Mode) (Mode, error) {
	if mode == "" {
		return ModeAuto, nil
	}
	switch mode {
	case ModeAuto, ModeV1, ModeV2:
		return mode, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidMode, mode)
	}
}

func selectedMode(a *archive, requested Mode) (Mode, error) {
	mode, err := normalizeMode(requested)
	if err != nil {
		return "", err
	}
	hasV2, hasV3 := archiveModernPairs(a)
	hasModern := hasV2 || hasV3
	switch mode {
	case ModeAuto:
		if hasModern {
			return ModeV2, nil
		}
		return ModeV1, nil
	case ModeV1:
		if hasModern {
			return "", fmt.Errorf("%w: V2/V3 signature present", ErrInvalidMode)
		}
		return ModeV1, nil
	case ModeV2:
		if a.block == nil {
			return "", ErrNoSigningBlock
		}
		return ModeV2, nil
	default:
		return "", ErrInvalidMode
	}
}

func detectArchive(a *archive) (Detection, error) {
	var detection Detection
	hasV2, hasV3 := archiveModernPairs(a)
	detection.HasV2 = hasV2
	detection.HasV3 = hasV3
	detection.HasV31 = hasPairID(a, apksigblock.IDV31Signature)
	detection.HasV1 = hasV1Signature(a.entries)
	if _, _, err := parseV1Comment(v1Comment(a)); err != nil {
		detection.Warnings = append(detection.Warnings, err.Error())
	}
	if hasV2 || hasV3 {
		detection.Mode = ModeV2
	} else {
		detection.Mode = ModeV1
	}
	verification, err := verifyArchive(a)
	if err != nil {
		return detection, err
	}
	detection.Verified = verification.Verified
	if len(verification.Warnings) > 0 {
		detection.Warnings = append(detection.Warnings, verification.Warnings...)
	}
	if len(verification.Errors) > 0 {
		detection.Warnings = append(detection.Warnings, verification.Errors...)
	}
	return detection, nil
}

func hasV1Signature(entries []zippkg.CDEntry) bool {
	manifest := false
	signatureFiles := make(map[string]bool)
	for _, entry := range entries {
		switch {
		case entry.Name == "META-INF/MANIFEST.MF":
			manifest = true
		case strings.HasPrefix(entry.Name, "META-INF/") && strings.HasSuffix(entry.Name, ".SF"):
			signatureFiles[strings.TrimSuffix(entry.Name, ".SF")] = true
		}
	}
	if !manifest {
		return false
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name, "META-INF/") {
			continue
		}
		for _, suffix := range []string{".RSA", ".DSA", ".EC"} {
			if strings.HasSuffix(entry.Name, suffix) && signatureFiles[strings.TrimSuffix(entry.Name, suffix)] {
				return true
			}
		}
	}
	return false
}

func archiveModernPairs(a *archive) (hasV2, hasV3 bool) {
	if a == nil || a.block == nil {
		return false, false
	}
	return modernPair(a.block.Pairs)
}

func Detect(r io.ReaderAt, size int64) (Detection, error) {
	a, err := loadArchive(r, size)
	if err != nil {
		return Detection{}, err
	}
	return detectArchive(a)
}

func ReadChannel(r io.ReaderAt, size int64) (string, error) {
	return ReadChannelWithBlockID(r, size, 0)
}

func ReadChannelWithBlockID(r io.ReaderAt, size int64, blockID uint32) (string, error) {
	if blockID != 0 {
		if err := ValidateBlockID(blockID); err != nil {
			return "", err
		}
	}
	a, err := loadArchive(r, size)
	if err != nil {
		return "", err
	}
	if a.block != nil {
		if blockID != 0 {
			id := normalizeBlockID(blockID)
			value, found, err := channelPair(a.block, id)
			if err != nil {
				return "", err
			}
			if found && id == WallePairID {
				var object struct {
					Channel string `json:"channel"`
				}
				if err := json.Unmarshal(value, &object); err != nil {
					return "", err
				}
				return object.Channel, nil
			}
			if found {
				return string(value), nil
			}
			// A V1 channel remains the fallback when the requested pair is absent.
			return readV1(a)
		}
		if value, found, err := channelPair(a.block, ChannelPairID); err != nil {
			return "", err
		} else if found {
			return string(value), nil
		}
		if value, found, err := channelPair(a.block, WallePairID); err != nil {
			return "", err
		} else if found {
			var object struct {
				Channel string `json:"channel"`
			}
			if err := json.Unmarshal(value, &object); err != nil {
				return "", err
			}
			return object.Channel, nil
		}
	}
	return readV1(a)
}
