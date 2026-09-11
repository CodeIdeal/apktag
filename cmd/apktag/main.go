package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	apktag "github.com/CodeIdeal/apktag"
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

func runPut(args []string) error {
	flags := flag.NewFlagSet("put", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
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
	channels, err := channelsFromSpec(*channelsSpec)
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
	artifacts, err := apktag.PackFiles(base, channels, options)
	if err != nil {
		return err
	}
	for _, artifact := range artifacts {
		fmt.Println(artifact.Path)
	}
	return nil
}

func runGet(args []string) error {
	flags := flag.NewFlagSet("get", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	apkPath := flags.String("c", "", "APK path")
	showStatus := flags.Bool("s", false, "show signing mode and verification status")
	blockIDValue := flags.String("block-id", "VasDolly", "Signing Block ID: VasDolly, Walle, or a 32-bit hexadecimal value")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
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
		detection, err := apktag.Detect(file, info.Size())
		if err != nil {
			return err
		}
		fmt.Printf("mode=%s verified=%t v1=%t v2=%t v3=%t v31=%t\n", detection.Mode, detection.Verified, detection.HasV1, detection.HasV2, detection.HasV3, detection.HasV31)
		return nil
	}
	blockID, err := parseBlockID(*blockIDValue)
	if err != nil {
		return err
	}
	channel, err := apktag.ReadChannelWithBlockID(file, info.Size(), blockID)
	if err != nil {
		return err
	}
	fmt.Println(channel)
	return nil
}

func runRemove(args []string) error {
	flags := flag.NewFlagSet("remove", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
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
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var output bytes.Buffer
	blockID, err := parseBlockID(*blockIDValue)
	if err != nil {
		return err
	}
	if err := apktag.RemoveChannel(bytes.NewReader(data), int64(len(data)), &output, apktag.TransformOptions{Mode: apktag.Mode(*mode), BlockID: blockID, VerifyInput: !*noVerify}); err != nil {
		return err
	}
	destination := ""
	if len(positional) > 0 {
		destination = positional[0]
	}
	if destination != "" {
		return atomicWrite(destination, output.Bytes())
	}
	return atomicWrite(path, output.Bytes())
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

func channelsFromSpec(spec string) ([]string, error) {
	if info, err := os.Stat(spec); err == nil && !info.IsDir() {
		data, readErr := os.ReadFile(spec)
		if readErr != nil {
			return nil, readErr
		}
		return splitChannels(string(data)), nil
	}
	return splitChannels(spec), nil
}

func splitChannels(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
}

func atomicWrite(path string, data []byte) error {
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
			_ = os.Remove(temporaryName)
		}
	}()
	if _, err := temporary.Write(data); err != nil {
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
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	keep = true
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: apktag <put|get|remove> [options]")
	fmt.Fprintln(os.Stderr, "  apktag put -c channel1,channel2 base.apk out-dir/")
	fmt.Fprintln(os.Stderr, "  apktag get -c channel.apk")
	fmt.Fprintln(os.Stderr, "  apktag get -s channel.apk")
	fmt.Fprintln(os.Stderr, "  apktag remove -c channel.apk [cleaned.apk]")
}
