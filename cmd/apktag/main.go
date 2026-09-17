package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	apktag "github.com/CodeIdeal/apktag"
	"github.com/CodeIdeal/apktag/internal/logging"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "apktag:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("a command is required")
	}
	switch args[0] {
	case "put":
		return runPut(args[1:])
	case "get":
		return runGet(args[1:])
	case "remove":
		return runRemove(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runPut(args []string) (err error) {
	flags := flag.NewFlagSet("put", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	logLevel := flags.String("log-level", "info", "log level: debug, info, warn, error, off")
	channelsSpec := flags.String("c", "", "comma-separated channels or a file with one channel per line")
	mode := flags.String("mode", "auto", "auto, v1, or v2")
	out := flags.String("out", "", "output directory, or exact output path for one channel")
	pattern := flags.String("pattern", "", "output filename pattern")
	overwrite := flags.Bool("overwrite", false, "replace existing outputs")
	workers := flags.Int("workers", 0, "number of concurrent workers")
	noVerify := flags.Bool("no-verify", false, "skip signature verification")
	blockIDValue := flags.String("block-id", "VasDolly", "Signing Block ID: VasDolly, Walle, or a 32-bit hexadecimal value")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	logger, err := commandLogger(*logLevel)
	if err != nil {
		return err
	}
	apktag.SetLogger(logger)
	op := logging.New(logger, "cli_put")
	var errorReported bool
	defer func() {
		if errorReported {
			op.FinishReported(err)
		} else {
			op.Finish(err)
		}
	}()
	op.Step("validate_arguments")
	op.Debug("arguments parsed")

	if *channelsSpec == "" || flags.NArg() < 1 {
		return errors.New("put requires -c and a base APK path")
	}
	positional := flags.Args()
	if *out != "" && len(positional) != 1 {
		return errors.New("put accepts one base APK path when --out is set")
	}
	if *out == "" && len(positional) > 2 {
		return errors.New("put accepts a base APK path and optional output directory")
	}
	op.Step("read_channels")
	channels, err := channelsFromSpec(*channelsSpec, op)
	if err != nil {
		return err
	}
	blockID, err := parseBlockID(*blockIDValue)
	if err != nil {
		return err
	}
	base := positional[0]
	options := apktag.BatchOptions{
		TransformOptions: apktag.TransformOptions{Mode: apktag.Mode(*mode), BlockID: blockID, VerifyInput: !*noVerify},
		OutputDir:        "",
		OutputPattern:    *pattern,
		Overwrite:        *overwrite,
		Workers:          *workers,
	}
	if *out != "" {
		if len(channels) == 1 && strings.EqualFold(filepath.Ext(*out), ".apk") {
			options.OutputDir = filepath.Dir(*out)
			options.OutputPattern = filepath.Base(*out)
		} else {
			options.OutputDir = *out
		}
	} else if len(positional) == 2 {
		output := positional[1]
		if len(channels) == 1 && strings.EqualFold(filepath.Ext(output), ".apk") {
			options.OutputDir = filepath.Dir(output)
			options.OutputPattern = filepath.Base(output)
		} else {
			options.OutputDir = output
		}
	}
	op.Step("pack_files")
	artifacts, err := apktag.PackFiles(base, channels, options)
	if err != nil {
		errorReported = true
		return err
	}
	op.Step("print_results")
	for _, artifact := range artifacts {
		fmt.Println(artifact.Path)
	}
	return nil
}

func runGet(args []string) (err error) {
	flags := flag.NewFlagSet("get", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	logLevel := flags.String("log-level", "info", "log level: debug, info, warn, error, off")
	apkPath := flags.String("c", "", "APK path")
	showStatus := flags.Bool("s", false, "show signing mode and verification status")
	blockIDValue := flags.String("block-id", "VasDolly", "Signing Block ID: VasDolly, Walle, or a 32-bit hexadecimal value")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	logger, err := commandLogger(*logLevel)
	if err != nil {
		return err
	}
	apktag.SetLogger(logger)
	op := logging.New(logger, "cli_get")
	var errorReported bool
	defer func() {
		if errorReported {
			op.FinishReported(err)
		} else {
			op.Finish(err)
		}
	}()
	op.Step("validate_arguments")
	op.Debug("arguments parsed")

	path := *apkPath
	positional := flags.Args()
	if path != "" && len(positional) > 0 {
		return errors.New("get accepts either -c or one APK path, not both")
	}
	if path == "" && len(positional) > 1 {
		return errors.New("get accepts one APK path")
	}
	if path == "" && len(positional) == 1 {
		path = positional[0]
	}
	if path == "" {
		return errors.New("get requires an APK path")
	}
	op.Step("open_apk")
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if *showStatus {
		op.Step("detect")
		detection, err := apktag.Detect(file, info.Size())
		if err != nil {
			errorReported = true
			return err
		}
		fmt.Printf("mode=%s verified=%t v1=%t v2=%t v3=%t v31=%t\n", detection.Mode, detection.Verified, detection.HasV1, detection.HasV2, detection.HasV3, detection.HasV31)
		return nil
	}
	blockID, err := parseBlockID(*blockIDValue)
	if err != nil {
		return err
	}
	op.Step("read_channel")
	channel, err := apktag.ReadChannelWithBlockID(file, info.Size(), blockID)
	if err != nil {
		errorReported = true
		return err
	}
	fmt.Println(channel)
	return nil
}

func runRemove(args []string) (err error) {
	flags := flag.NewFlagSet("remove", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	logLevel := flags.String("log-level", "info", "log level: debug, info, warn, error, off")
	input := flags.String("c", "", "APK path")
	mode := flags.String("mode", "auto", "auto, v1, or v2")
	noVerify := flags.Bool("no-verify", false, "skip signature verification")
	blockIDValue := flags.String("block-id", "VasDolly", "Signing Block ID: VasDolly, Walle, or a 32-bit hexadecimal value")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	logger, err := commandLogger(*logLevel)
	if err != nil {
		return err
	}
	apktag.SetLogger(logger)
	op := logging.New(logger, "cli_remove")
	var errorReported bool
	defer func() {
		if errorReported {
			op.FinishReported(err)
		} else {
			op.Finish(err)
		}
	}()
	op.Step("validate_arguments")
	op.Debug("arguments parsed")

	path := *input
	positional := flags.Args()
	if path != "" {
		if len(positional) > 1 {
			return errors.New("remove accepts one optional destination when -c is set")
		}
	} else {
		if len(positional) > 2 {
			return errors.New("remove accepts an APK path and optional destination")
		}
		if len(positional) > 0 {
			path = positional[0]
			positional = positional[1:]
		}
	}
	if path == "" {
		return errors.New("remove requires an APK path")
	}
	op.Step("read_apk")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var output bytes.Buffer
	blockID, err := parseBlockID(*blockIDValue)
	if err != nil {
		return err
	}
	op.Step("remove_channel")
	if err := apktag.RemoveChannel(bytes.NewReader(data), int64(len(data)), &output, apktag.TransformOptions{Mode: apktag.Mode(*mode), BlockID: blockID, VerifyInput: !*noVerify}); err != nil {
		errorReported = true
		return err
	}
	destination := ""
	if len(positional) > 0 {
		destination = positional[0]
	}
	if destination != "" {
		return atomicWrite(destination, output.Bytes(), op)
	}
	return atomicWrite(path, output.Bytes(), op)
}

func parseBlockID(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	switch strings.ToLower(value) {
	case "vasdolly":
		return apktag.ChannelPairID, nil
	case "walle":
		return apktag.WallePairID, nil
	}
	if len(value) < 3 || !(strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X")) {
		return 0, fmt.Errorf("invalid block ID %q: use VasDolly, Walle, or a 0x-prefixed 32-bit hexadecimal value", value)
	}
	parsed, err := strconv.ParseUint(value[2:], 16, 32)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("invalid block ID %q: use VasDolly, Walle, or a non-zero 0x-prefixed 32-bit hexadecimal value", value)
	}
	blockID := uint32(parsed)
	if err := apktag.ValidateBlockID(blockID); err != nil {
		return 0, fmt.Errorf("invalid block ID %q: %w", value, err)
	}
	return blockID, nil
}

func channelsFromSpec(spec string, op *logging.Operation) ([]string, error) {
	if info, err := os.Stat(spec); err == nil && !info.IsDir() {
		op.Debug("reading channel file", "path", spec)
		data, readErr := os.ReadFile(spec)
		if readErr != nil {
			return nil, readErr
		}
		op.Debug("channel file read", "path", spec, "bytes", len(data))
		return splitChannels(string(data)), nil
	}
	op.Debug("reading inline channels")
	return splitChannels(spec), nil
}

func splitChannels(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
}

func atomicWrite(path string, data []byte, op *logging.Operation) error {
	op.Step("create_temporary_file")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".apktag-cli-*")
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
	if _, err := temporary.Write(data); err != nil {
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
	op.Step("rename_output")
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	keep = true
	op.Info("output committed", "path", path, "bytes", len(data), "status", "completed")
	return nil
}

// disabledHandler disables every level, including custom slog levels.
type disabledHandler struct{ slog.Handler }

func (disabledHandler) Enabled(context.Context, slog.Level) bool { return false }
func (h disabledHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return disabledHandler{h.Handler.WithAttrs(attrs)}
}
func (h disabledHandler) WithGroup(name string) slog.Handler {
	return disabledHandler{h.Handler.WithGroup(name)}
}

func commandLogger(value string) (*slog.Logger, error) {
	var level slog.Level
	switch value {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	case "off":
		return slog.New(disabledHandler{slog.NewTextHandler(os.Stderr, nil)}), nil
	default:
		return nil, fmt.Errorf("invalid log level %q: use debug, info, warn, error, or off", value)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})), nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "logging: --log-level debug|info|warn|error|off (default info; stderr)")
	fmt.Fprintln(os.Stderr, "usage: apktag <put|get|remove> [options]")
	fmt.Fprintln(os.Stderr, "  apktag put -c channel1,channel2 base.apk out-dir/")
	fmt.Fprintln(os.Stderr, "  apktag get -c channel.apk")
	fmt.Fprintln(os.Stderr, "  apktag get -s channel.apk")
	fmt.Fprintln(os.Stderr, "  apktag remove -c channel.apk [cleaned.apk]")
}
