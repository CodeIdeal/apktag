// Package vasdolly reads, writes, and removes VasDolly channel metadata from
// Android APK files without re-signing them.
package vasdolly

import (
	"io"

	"github.com/CodeIdeal/VasDolly-go/internal/core"
)

// Mode selects the channel storage scheme.
type Mode = core.Mode

const (
	ModeAuto = core.ModeAuto
	ModeV1   = core.ModeV1
	ModeV2   = core.ModeV2
)

// TransformOptions controls a single APK transformation.
type TransformOptions = core.TransformOptions

// BatchOptions controls PackFiles.
type BatchOptions = core.BatchOptions

// Detection describes the schemes found in an APK.
type Detection = core.Detection

// Artifact identifies one output produced by PackFiles.
type Artifact = core.Artifact

// ChannelPairID is the VasDolly ID-value pair identifier used in an APK
// Signing Block.
const ChannelPairID = core.ChannelPairID

// WallePairID is Walle's channel pair identifier. Its value is JSON encoded.
const WallePairID = core.WallePairID

// V1Marker terminates the VasDolly V1 ZIP comment suffix.
const V1Marker = core.V1Marker

var (
	ErrChannelExists   = core.ErrChannelExists
	ErrChannelNotFound = core.ErrChannelNotFound
	ErrInvalidChannel  = core.ErrInvalidChannel
	ErrInvalidMode     = core.ErrInvalidMode
	ErrReservedBlockID = core.ErrReservedBlockID
	ErrNoSigningBlock  = core.ErrNoSigningBlock
	ErrUnverifiedInput = core.ErrUnverifiedInput
)

// ValidateBlockID rejects Android-reserved APK Signing Block IDs. Zero is
// valid and selects ChannelPairID when used in TransformOptions.
func ValidateBlockID(blockID uint32) error {
	return core.ValidateBlockID(blockID)
}

// Pack adds channel metadata to an APK and writes the result to w. The input
// ReaderAt is never modified. Set VerifyInput to verify the selected signing
// scheme before writing; structural checks always run.
func Pack(r io.ReaderAt, size int64, channel string, w io.Writer, opts TransformOptions) error {
	return core.Pack(r, size, channel, w, opts)
}

// RemoveChannel removes channel metadata according to opts. Auto mode removes
// both V2/V3 and V1 metadata when both are present; explicit modes only touch
// their selected representation.
func RemoveChannel(r io.ReaderAt, size int64, w io.Writer, opts TransformOptions) error {
	return core.RemoveChannel(r, size, w, opts)
}

// Detect reports the signing schemes found in an APK.
func Detect(r io.ReaderAt, size int64) (Detection, error) {
	return core.Detect(r, size)
}

// ReadChannel reads VasDolly channel metadata from an APK.
func ReadChannel(r io.ReaderAt, size int64) (string, error) {
	return core.ReadChannel(r, size)
}

// ReadChannelWithBlockID reads channel metadata from a specific Signing Block pair.
// A zero block ID preserves the default auto-detection behavior.
func ReadChannelWithBlockID(r io.ReaderAt, size int64, blockID uint32) (string, error) {
	return core.ReadChannelWithBlockID(r, size, blockID)
}

// PackFiles creates one independent artifact per channel. The base APK is
// loaded once and is never modified. Results retain the input channel order.
func PackFiles(basePath string, channels []string, opts BatchOptions) ([]Artifact, error) {
	return core.PackFiles(basePath, channels, opts)
}
