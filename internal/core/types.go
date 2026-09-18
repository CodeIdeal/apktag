package core

// Mode selects the channel storage scheme.
type Mode string

const (
	ModeAuto Mode = "auto"
	ModeV1   Mode = "v1"
	ModeV2   Mode = "v2"
)

// TransformOptions controls a single APK transformation.
type TransformOptions struct {
	Mode Mode
	// BlockID selects the APK Signing Block pair used for channel metadata.
	// Zero selects the default VasDolly ID. Android-reserved IDs are rejected.
	BlockID uint32

	// VerifyInput asks Pack and Remove to verify the selected signing scheme
	// before transforming. Structural validation is always performed.
	VerifyInput bool

	// Logger receives VasDolly-compatible log messages. If nil, global logger is used.
	Logger Logger

	// ApkPath is an optional display path of the base APK for log messages.
	ApkPath string

	// DestPath is an optional display path of the target APK for log messages.
	DestPath string
}

// BatchOptions controls PackFiles.
type BatchOptions struct {
	TransformOptions
	OutputDir     string
	OutputPattern string
	Overwrite     bool
	Workers       int
}

// Detection describes the schemes found in an APK. Mode is the preferred
// transformation mode (V3/V2 signing block before V1).
type Detection struct {
	Mode     Mode
	HasV1    bool
	HasV2    bool
	HasV3    bool
	HasV31   bool
	Verified bool
	Warnings []string
}

// Artifact identifies one output produced by PackFiles.
type Artifact struct {
	Channel string
	Path    string
	Mode    Mode
}
