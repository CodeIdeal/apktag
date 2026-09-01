package vasdolly

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

	// VerifyInput asks Pack and Remove to verify the selected signing scheme
	// before transforming. Structural validation is always performed.
	VerifyInput bool
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
