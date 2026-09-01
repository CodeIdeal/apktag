package vasdolly

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
	"github.com/agusibrahim/apksig-go/pkg/apkverifier"
	"github.com/agusibrahim/apksig-go/pkg/apkwriter"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/signer"
	"github.com/agusibrahim/apksig-go/pkg/v1signer"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

const testManifestBase64 = "AwAIAGgEAAABABwAqAIAABQAAAAAAAAAAAAAAGwAAAAAAAAAAAAAABoAAAA0AAAAWgAAAJAAAACuAAAAvAAAAM4AAAAmAQAAKgEAADwBAABwAQAApAEAALgBAADkAQAA6gEAAPIBAAD6AQAADgIAACgCAAALAHYAZQByAHMAaQBvAG4AQwBvAGQAZQAAAAsAdgBlAHIAcwBpAG8AbgBOAGEAbQBlAAAAEQBjAG8AbQBwAGkAbABlAFMAZABrAFYAZQByAHMAaQBvAG4AAAAZAGMAbwBtAHAAaQBsAGUAUwBkAGsAVgBlAHIAcwBpAG8AbgBDAG8AZABlAG4AYQBtAGUAAAANAG0AaQBuAFMAZABrAFYAZQByAHMAaQBvAG4AAAAFAGwAYQBiAGUAbAAAAAcAYQBuAGQAcgBvAGkAZAAAACoAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AYQBuAGQAcgBvAGkAZAAuAGMAbwBtAC8AYQBwAGsALwByAGUAcwAvAGEAbgBkAHIAbwBpAGQAAAAAAAAABwBwAGEAYwBrAGEAZwBlAAAAGABwAGwAYQB0AGYAbwByAG0AQgB1AGkAbABkAFYAZQByAHMAaQBvAG4AQwBvAGQAZQAAABgAcABsAGEAdABmAG8AcgBtAEIAdQBpAGwAZABWAGUAcgBzAGkAbwBuAE4AYQBtAGUAAAAIAG0AYQBuAGkAZgBlAHMAdAAAABQAYwBvAG0ALgBlAHgAYQBtAHAAbABlAC4AdgBhAHMAZABvAGwAbAB5AAAAAQAxAAAAAgAxADcAAAACADMANwAAAAgAdQBzAGUAcwAtAHMAZABrAAAACwBhAHAAcABsAGkAYwBhAHQAaQBvAG4AAAAIAFYAYQBzAEQAbwBsAGwAeQAAAIABCAAgAAAAGwIBARwCAQFyBQEBcwUBAQwCAQEBAAEBAAEQABgAAAABAAAA/////wYAAAAHAAAAAgEQALAAAAABAAAA//////////8MAAAAFAAUAAcAAAAAAAAABwAAAAAAAAD/////CAAAEAEAAAAHAAAAAQAAAA4AAAAIAAADDgAAAAcAAAACAAAA/////wgAABAlAAAABwAAAAMAAAAPAAAACAAAAw8AAAD/////CQAAAA0AAAAIAAADDQAAAP////8KAAAAEAAAAAgAABAlAAAA/////wsAAAAPAAAACAAAEBEAAAACARAAOAAAAAEAAAD//////////xEAAAAUABQAAQAAAAAAAAAHAAAABAAAAP////8IAAAQGAAAAAMBEAAYAAAAAQAAAP//////////EQAAAAIBEAA4AAAAAQAAAP//////////EgAAABQAFAABAAAAAAAAAAcAAAAFAAAAEwAAAAgAAAMTAAAAAwEQABgAAAABAAAA//////////8SAAAAAwEQABgAAAABAAAA//////////8MAAAAAQEQABgAAAABAAAA/////wYAAAAHAAAA"

func testManifest(t *testing.T) []byte {
	t.Helper()
	manifest, err := base64.StdEncoding.DecodeString(testManifestBase64)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func makeZIP(t *testing.T, comment string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	writer.SetComment(comment)
	manifest, err := writer.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Write(testManifest(t)); err != nil {
		t.Fatal(err)
	}
	entry, err := writer.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("dex fixture")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func addSigningBlock(t *testing.T, input []byte, pairs []apksigblock.Pair) []byte {
	t.Helper()
	ds := datasource.NewBytes(input)
	eocd, err := zippkg.FindEOCD(ds)
	if err != nil {
		t.Fatal(err)
	}
	block, err := assembleSigningBlock(pairs)
	if err != nil {
		t.Fatal(err)
	}
	output := make([]byte, 0, len(input)+len(block))
	output = append(output, input[:int(eocd.CDStartOffset)]...)
	output = append(output, block...)
	output = append(output, input[int(eocd.CDStartOffset):]...)
	newOffset := uint32(eocd.CDStartOffset + int64(len(block)))
	binary.LittleEndian.PutUint32(output[len(output)-len(eocd.Bytes)+16:len(output)-len(eocd.Bytes)+20], newOffset)
	return output
}

func TestV1PackReadRemovePreservesComment(t *testing.T) {
	input := makeZIP(t, "ordinary-comment")
	var packed bytes.Buffer
	if err := Pack(bytes.NewReader(input), int64(len(input)), "渠道", &packed, TransformOptions{Mode: ModeV1}); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len())); err != nil || got != "渠道" {
		t.Fatalf("ReadChannel = %q, %v", got, err)
	}
	if bytes.Contains(packed.Bytes(), []byte("ordinary-comment渠道")) == false {
		t.Fatal("original comment was not preserved")
	}
	var removed bytes.Buffer
	if err := RemoveChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()), &removed, TransformOptions{Mode: ModeV1}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(removed.Bytes(), input) {
		t.Fatal("V1 removal did not restore the original APK bytes")
	}
	if got := string(zipComment(t, removed.Bytes())); got != "ordinary-comment" {
		t.Fatalf("comment after remove = %q", got)
	}
}

func TestV1RejectsDuplicateAndOverflow(t *testing.T) {
	input := makeZIP(t, "")
	var packed bytes.Buffer
	if err := Pack(bytes.NewReader(input), int64(len(input)), "one", &packed, TransformOptions{Mode: ModeV1}); err != nil {
		t.Fatal(err)
	}
	var duplicate bytes.Buffer
	if err := Pack(bytes.NewReader(packed.Bytes()), int64(packed.Len()), "two", &duplicate, TransformOptions{Mode: ModeV1}); err == nil {
		t.Fatal("duplicate channel was accepted")
	}
	large := strings.Repeat("x", 32768)
	if err := Pack(bytes.NewReader(input), int64(len(input)), large, io.Discard, TransformOptions{Mode: ModeV1}); err == nil {
		t.Fatal("oversized channel was accepted")
	}
}

func TestV1RejectsMalformedArchiveWithoutOutput(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{name: "truncated", data: []byte("PK\x05")},
		{name: "bad central directory offset", data: mutateEOCD(makeZIP(t, ""), func(eocd []byte) {
			binary.LittleEndian.PutUint32(eocd[16:20], ^uint32(0))
		})},
		{name: "zip64 sentinel", data: mutateEOCD(makeZIP(t, ""), func(eocd []byte) {
			binary.LittleEndian.PutUint16(eocd[10:12], ^uint16(0))
		})},
		{name: "multi-disk", data: mutateEOCD(makeZIP(t, ""), func(eocd []byte) {
			binary.LittleEndian.PutUint16(eocd[4:6], 1)
		})},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var output bytes.Buffer
			err := Pack(bytes.NewReader(testCase.data), int64(len(testCase.data)), "bad", &output, TransformOptions{Mode: ModeV1})
			if err == nil {
				t.Fatal("malformed archive was accepted")
			}
			if output.Len() != 0 {
				t.Fatalf("output was written after failure: %d bytes", output.Len())
			}
		})
	}
}

func TestV1CommentOverflowIsRejected(t *testing.T) {
	input := makeZIP(t, strings.Repeat("c", 65530))
	var output bytes.Buffer
	if err := Pack(bytes.NewReader(input), int64(len(input)), "x", &output, TransformOptions{Mode: ModeV1}); err == nil {
		t.Fatal("comment overflow was accepted")
	}
	if output.Len() != 0 {
		t.Fatal("output was written after comment overflow")
	}
}

func TestV2PairRewritePreservesUnknownPair(t *testing.T) {
	input := addSigningBlock(t, makeZIP(t, ""), []apksigblock.Pair{{ID: 0x12345678, Value: []byte("keep")}})
	var packed bytes.Buffer
	if err := Pack(bytes.NewReader(input), int64(len(input)), "play", &packed, TransformOptions{Mode: ModeV2}); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len())); err != nil || got != "play" {
		t.Fatalf("ReadChannel = %q, %v", got, err)
	}
	loaded, err := loadArchive(bytes.NewReader(packed.Bytes()), int64(packed.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.block == nil || len(loaded.block.Pairs) != 3 {
		t.Fatalf("unexpected pairs: %#v", loaded.block)
	}
	if loaded.block.Pairs[0].ID != 0x12345678 || string(loaded.block.Pairs[0].Value) != "keep" {
		t.Fatal("unknown pair changed")
	}
	if len(packed.Bytes()) < 4096 || (loaded.block.CDOffset-loaded.block.StartOffset)%4096 != 0 {
		t.Fatal("signing block is not aligned")
	}
	var removed bytes.Buffer
	if err := RemoveChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()), &removed, TransformOptions{Mode: ModeV2}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadChannel(bytes.NewReader(removed.Bytes()), int64(removed.Len())); err == nil {
		t.Fatal("removed channel remained readable")
	}
}

func TestV2PackPreservesSignature(t *testing.T) {
	algorithm, ok := algo.ByID(algo.SigRSAPKCS1SHA256)
	if !ok {
		t.Fatal("algorithm not found")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var signed bytes.Buffer
	writer := &apkwriter.SignedAPKWriter{
		Src: datasource.NewBytes(makeZIP(t, "")),
		Signers: []*signer.SignerConfig{{
			PrivateKey: key,
			Certs:      []*x509.Certificate{certificate},
			Algorithms: []algo.Algorithm{algorithm},
		}},
	}
	if err := writer.Write(&signed); err != nil {
		t.Fatal(err)
	}
	before, err := apkverifier.Verify(datasource.NewBytes(signed.Bytes()), 0, 0)
	if err != nil || !before.V2Verified {
		t.Fatalf("input verification = %#v, %v", before, err)
	}
	var packed bytes.Buffer
	if err := Pack(bytes.NewReader(signed.Bytes()), int64(signed.Len()), "signed", &packed, TransformOptions{Mode: ModeAuto, VerifyInput: true}); err != nil {
		t.Fatal(err)
	}
	after, err := apkverifier.Verify(datasource.NewBytes(packed.Bytes()), 0, 0)
	if err != nil || !after.V2Verified {
		t.Fatalf("output verification = %#v, %v", after, err)
	}
	if channel, err := ReadChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len())); err != nil || channel != "signed" {
		t.Fatalf("channel = %q, %v", channel, err)
	}
}

func TestV3PackPreservesSignature(t *testing.T) {
	algorithm, ok := algo.ByID(algo.SigRSAPKCS1SHA256)
	if !ok {
		t.Fatal("algorithm not found")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "v3-fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var signed bytes.Buffer
	writer := &apkwriter.SignedAPKWriter{
		Src: datasource.NewBytes(makeZIP(t, "")),
		Signers: []*signer.SignerConfig{{
			PrivateKey: key,
			Certs:      []*x509.Certificate{certificate},
			Algorithms: []algo.Algorithm{algorithm},
		}},
		V3MinSdk: 28,
		V3MaxSdk: 35,
	}
	if err := writer.Write(&signed); err != nil {
		t.Fatal(err)
	}
	before, err := apkverifier.Verify(datasource.NewBytes(signed.Bytes()), 0, 0)
	if err != nil || !before.V3Verified {
		t.Fatalf("input verification = %#v, %v", before, err)
	}
	var packed bytes.Buffer
	if err := Pack(bytes.NewReader(signed.Bytes()), int64(signed.Len()), "v3", &packed, TransformOptions{Mode: ModeAuto, VerifyInput: true}); err != nil {
		t.Fatal(err)
	}
	after, err := apkverifier.Verify(datasource.NewBytes(packed.Bytes()), 0, 0)
	if err != nil || !after.V3Verified {
		t.Fatalf("output verification = %#v, %v", after, err)
	}
}

func TestV31PackAndRemovePreserveSignatures(t *testing.T) {
	algorithm, ok := algo.ByID(algo.SigRSAPKCS1SHA256)
	if !ok {
		t.Fatal("algorithm not found")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "v31-fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var signed bytes.Buffer
	writer := &apkwriter.SignedAPKWriter{
		Src: datasource.NewBytes(makeZIP(t, "")),
		Signers: []*signer.SignerConfig{{
			PrivateKey: key,
			Certs:      []*x509.Certificate{certificate},
			Algorithms: []algo.Algorithm{algorithm},
		}},
		V3MinSdk:  28,
		V3MaxSdk:  35,
		V31MinSdk: 33,
		V31MaxSdk: 35,
	}
	if err := writer.Write(&signed); err != nil {
		t.Fatal(err)
	}
	before, err := apkverifier.Verify(datasource.NewBytes(signed.Bytes()), 0, 0)
	if err != nil || !before.V2Verified || !before.V3Verified || !before.V31Verified {
		t.Fatalf("input verification = %#v, %v", before, err)
	}
	inputArchive, err := loadArchive(bytes.NewReader(signed.Bytes()), int64(signed.Len()))
	if err != nil {
		t.Fatal(err)
	}
	originalValues := make(map[uint32][]byte)
	for _, pair := range inputArchive.block.Pairs {
		if pair.ID != apksigblock.IDPaddingPair {
			originalValues[pair.ID] = append([]byte(nil), pair.Value...)
		}
	}
	var packed bytes.Buffer
	if err := Pack(bytes.NewReader(signed.Bytes()), int64(signed.Len()), "v31", &packed, TransformOptions{Mode: ModeV2, VerifyInput: true}); err != nil {
		t.Fatal(err)
	}
	packedArchive, err := loadArchive(bytes.NewReader(packed.Bytes()), int64(packed.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range packedArchive.block.Pairs {
		if expected, ok := originalValues[pair.ID]; ok && !bytes.Equal(expected, pair.Value) {
			t.Fatalf("signature or metadata pair 0x%08x changed", pair.ID)
		}
	}
	after, err := apkverifier.Verify(datasource.NewBytes(packed.Bytes()), 0, 0)
	if err != nil || !after.V2Verified || !after.V3Verified || !after.V31Verified {
		t.Fatalf("packed verification = %#v, %v", after, err)
	}
	var removed bytes.Buffer
	if err := RemoveChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()), &removed, TransformOptions{Mode: ModeV2, VerifyInput: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadChannel(bytes.NewReader(removed.Bytes()), int64(removed.Len())); err == nil {
		t.Fatal("removed channel remained readable")
	}
	final, err := apkverifier.Verify(datasource.NewBytes(removed.Bytes()), 0, 0)
	if err != nil || !final.V2Verified || !final.V3Verified || !final.V31Verified {
		t.Fatalf("removed verification = %#v, %v", final, err)
	}
}

func TestSigningBlockRejectsMalformedPaddingAndKnownPairs(t *testing.T) {
	cases := []struct {
		name  string
		pairs []apksigblock.Pair
	}{
		{name: "duplicate v2", pairs: []apksigblock.Pair{{ID: apksigblock.IDV2Signature, Value: []byte("one")}, {ID: apksigblock.IDV2Signature, Value: []byte("two")}}},
		{name: "duplicate dependency info", pairs: []apksigblock.Pair{{ID: apksigblock.IDDependencyInfo, Value: []byte("one")}, {ID: apksigblock.IDDependencyInfo, Value: []byte("two")}}},
		{name: "duplicate channel", pairs: []apksigblock.Pair{{ID: ChannelPairID, Value: []byte("one")}, {ID: ChannelPairID, Value: []byte("two")}}},
		{name: "non-zero padding", pairs: []apksigblock.Pair{{ID: apksigblock.IDPaddingPair, Value: []byte{1}}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input := addSigningBlock(t, makeZIP(t, ""), testCase.pairs)
			var output bytes.Buffer
			err := Pack(bytes.NewReader(input), int64(len(input)), "bad", &output, TransformOptions{Mode: ModeV2})
			if err == nil {
				t.Fatal("malformed Signing Block was accepted")
			}
			if output.Len() != 0 {
				t.Fatalf("output was written after failure: %d bytes", output.Len())
			}
		})
	}
}

func TestSigningBlockBadMagicFailsClosedInAutoMode(t *testing.T) {
	input := addSigningBlock(t, makeZIP(t, ""), []apksigblock.Pair{{ID: 0x12345678, Value: []byte("keep")}})
	eocd, err := zippkg.FindEOCD(datasource.NewBytes(input))
	if err != nil {
		t.Fatal(err)
	}
	input[eocd.CDStartOffset-1] ^= 0x01
	var output bytes.Buffer
	if err := Pack(bytes.NewReader(input), int64(len(input)), "bad", &output, TransformOptions{Mode: ModeAuto}); err == nil {
		t.Fatal("APK with a damaged Signing Block magic was rewritten")
	}
	if output.Len() != 0 {
		t.Fatalf("output was written after failure: %d bytes", output.Len())
	}
}

func TestV1PackPreservesSignature(t *testing.T) {
	signed := makeV1SignedAPK(t)
	before, err := apkverifier.Verify(datasource.NewBytes(signed), 0, 0)
	if err != nil || !before.V1Verified {
		t.Fatalf("input verification = %#v, %v", before, err)
	}
	var packed bytes.Buffer
	if err := Pack(bytes.NewReader(signed), int64(len(signed)), "legacy", &packed, TransformOptions{Mode: ModeV1, VerifyInput: true}); err != nil {
		t.Fatal(err)
	}
	after, err := apkverifier.Verify(datasource.NewBytes(packed.Bytes()), 0, 0)
	if err != nil || !after.V1Verified {
		t.Fatalf("output verification = %#v, %v", after, err)
	}
}

func TestBatchOutputNaming(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.apk")
	if err := os.WriteFile(base, makeZIP(t, ""), 0o644); err != nil {
		t.Fatal(err)
	}
	artifacts, err := PackFiles(base, []string{"a", "b", "a"}, BatchOptions{OutputDir: dir, TransformOptions: TransformOptions{Mode: ModeV1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 || filepath.Base(artifacts[0].Path) != "a-base.apk" || filepath.Base(artifacts[1].Path) != "b-base.apk" {
		t.Fatalf("artifacts = %#v", artifacts)
	}
}

func TestPackFilesNormalizesChannelsAndPreservesBase(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "release.apk")
	base := makeZIP(t, "ordinary")
	if err := os.WriteFile(basePath, base, 0o644); err != nil {
		t.Fatal(err)
	}
	artifacts, err := PackFiles(basePath, []string{" \ufeff one ", "", "two", "one", "  two  "}, BatchOptions{
		OutputDir: filepath.Join(dir, "nested", "dist"),
		Workers:   2,
		TransformOptions: TransformOptions{
			Mode: ModeV1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 || artifacts[0].Channel != "one" || artifacts[1].Channel != "two" {
		t.Fatalf("artifacts = %#v", artifacts)
	}
	if filepath.Base(artifacts[0].Path) != "one-release.apk" || filepath.Base(artifacts[1].Path) != "two-release.apk" {
		t.Fatalf("paths = %#v", artifacts)
	}
	if got, err := os.ReadFile(basePath); err != nil || !bytes.Equal(got, base) {
		t.Fatalf("base APK changed: %v", err)
	}
	for _, artifact := range artifacts {
		data, readErr := os.ReadFile(artifact.Path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		channel, readErr := ReadChannel(bytes.NewReader(data), int64(len(data)))
		if readErr != nil || channel != artifact.Channel {
			t.Fatalf("artifact channel = %q, %v", channel, readErr)
		}
	}
}

func TestPackFilesRejectsUnsafePatternsBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.apk")
	base := makeZIP(t, "")
	if err := os.WriteFile(basePath, base, 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		pattern string
	}{
		{name: "traversal", pattern: "../{channel}.apk"},
		{name: "absolute", pattern: filepath.Join(dir, "{channel}.apk")},
		{name: "collision", pattern: "same.apk"},
		{name: "base path", pattern: "{base}.apk"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			outputDir := filepath.Join(dir, testCase.name)
			before, err := os.ReadFile(basePath)
			if err != nil {
				t.Fatal(err)
			}
			_, err = PackFiles(basePath, []string{"one", "two"}, BatchOptions{OutputDir: outputDir, OutputPattern: testCase.pattern, TransformOptions: TransformOptions{Mode: ModeV1}})
			if err == nil {
				t.Fatal("unsafe or colliding output pattern was accepted")
			}
			after, readErr := os.ReadFile(basePath)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatalf("base changed after rejected pattern: %v", readErr)
			}
		})
	}
}

func TestPackFilesOverwritePolicyAndOrderedResults(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.apk")
	if err := os.WriteFile(basePath, makeZIP(t, ""), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := PackFiles(basePath, []string{"a", "b", "c"}, BatchOptions{OutputDir: dir, Workers: 1, TransformOptions: TransformOptions{Mode: ModeV1}})
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{first[0].Channel, first[1].Channel, first[2].Channel}; !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("result order = %#v", got)
	}
	if _, err := PackFiles(basePath, []string{"a"}, BatchOptions{OutputDir: dir, TransformOptions: TransformOptions{Mode: ModeV1}}); err == nil {
		t.Fatal("existing output was silently replaced")
	}
	second, err := PackFiles(basePath, []string{"a"}, BatchOptions{OutputDir: dir, Overwrite: true, TransformOptions: TransformOptions{Mode: ModeV1}})
	if err != nil || len(second) != 1 {
		t.Fatalf("overwrite result = %#v, %v", second, err)
	}
}

func TestPackFilesPartialFailureDoesNotChangeBase(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.apk")
	base := makeZIP(t, "")
	if err := os.WriteFile(basePath, base, 0o644); err != nil {
		t.Fatal(err)
	}
	artifacts, err := PackFiles(basePath, []string{"ok"}, BatchOptions{OutputDir: dir, Workers: 1, TransformOptions: TransformOptions{Mode: ModeV1}})
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("initial artifact = %#v, %v", artifacts, err)
	}
	initialArtifact, err := os.ReadFile(artifacts[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = PackFiles(basePath, []string{strings.Repeat("x", 32768)}, BatchOptions{OutputDir: dir, Workers: 1, TransformOptions: TransformOptions{Mode: ModeV1}})
	if err == nil {
		t.Fatal("oversized channel did not fail")
	}
	after, readErr := os.ReadFile(basePath)
	if readErr != nil || !bytes.Equal(after, base) {
		t.Fatalf("base changed after partial failure: %v", readErr)
	}
	if data, readErr := os.ReadFile(artifacts[0].Path); readErr != nil || !bytes.Equal(data, initialArtifact) {
		t.Fatalf("existing artifact changed after failed batch: %v", readErr)
	}
}

func zipComment(t *testing.T, data []byte) []byte {
	t.Helper()
	eocd, err := zippkg.FindEOCD(datasource.NewBytes(data))
	if err != nil {
		t.Fatal(err)
	}
	return eocd.Bytes[22:]
}

func mutateEOCD(data []byte, mutate func([]byte)) []byte {
	copyData := append([]byte(nil), data...)
	eocd, err := zippkg.FindEOCD(datasource.NewBytes(copyData))
	if err != nil {
		panic(err)
	}
	mutate(copyData[int(eocd.Offset):])
	return copyData
}

func makeV1SignedAPK(t *testing.T) []byte {
	t.Helper()
	base := makeZIP(t, "")
	parsed, err := loadArchive(bytes.NewReader(base), int64(len(base)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "v1-fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := v1signer.Sign(parsed.ds, parsed.entries, &v1signer.SignerConfig{PrivateKey: key, Cert: certificate, Name: "CERT"})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(base), int64(len(base)))
	if err != nil {
		t.Fatal(err)
	}
	var signed bytes.Buffer
	zipWriter := zip.NewWriter(&signed)
	for _, file := range reader.File {
		header := file.FileHeader
		destination, createErr := zipWriter.CreateHeader(&header)
		if createErr != nil {
			t.Fatal(createErr)
		}
		source, openErr := file.Open()
		if openErr != nil {
			t.Fatal(openErr)
		}
		if _, copyErr := io.Copy(destination, source); copyErr != nil {
			source.Close()
			t.Fatal(copyErr)
		}
		source.Close()
	}
	for name, content := range map[string][]byte{
		"META-INF/MANIFEST.MF":                 signatures.Manifest,
		"META-INF/CERT.SF":                     signatures.SF,
		"META-INF/CERT" + signatures.Extension: signatures.PKCS7,
	} {
		entry, createErr := zipWriter.Create(name)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := entry.Write(content); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return signed.Bytes()
}

func makeModernSignedAPK(t *testing.T, v3, v31 bool) []byte {
	t.Helper()
	algorithm, ok := algo.ByID(algo.SigRSAPKCS1SHA256)
	if !ok {
		t.Fatal("algorithm not found")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "matrix-fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	writer := &apkwriter.SignedAPKWriter{
		Src: datasource.NewBytes(makeZIP(t, "")),
		Signers: []*signer.SignerConfig{{
			PrivateKey: key,
			Certs:      []*x509.Certificate{certificate},
			Algorithms: []algo.Algorithm{algorithm},
		}},
	}
	if v3 || v31 {
		writer.V3MinSdk = 28
		writer.V3MaxSdk = 35
	}
	if v31 {
		writer.V31MinSdk = 33
		writer.V31MaxSdk = 35
	}
	var signed bytes.Buffer
	if err := writer.Write(&signed); err != nil {
		t.Fatal(err)
	}
	return signed.Bytes()
}

func replaceSigningPairs(t *testing.T, data []byte, pairs []apksigblock.Pair) []byte {
	t.Helper()
	a, err := loadArchive(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	block, err := assembleSigningBlock(pairs)
	if err != nil {
		t.Fatal(err)
	}
	newCDOffset := a.block.StartOffset + int64(len(block))
	output := make([]byte, 0, int(a.block.StartOffset)+len(block)+len(a.data)-int(a.eocd.CDStartOffset))
	output = append(output, a.data[:int(a.block.StartOffset)]...)
	output = append(output, block...)
	output = append(output, a.data[int(a.eocd.CDStartOffset):]...)
	eocdOffset := len(output) - len(a.eocd.Bytes)
	binary.LittleEndian.PutUint32(output[eocdOffset+16:eocdOffset+20], uint32(newCDOffset))
	return output
}

func TestDetectSignatureMatrix(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		hasV1    bool
		hasV2    bool
		hasV3    bool
		hasV31   bool
		verified bool
		wantMode Mode
	}{
		{name: "unsigned", data: makeZIP(t, ""), wantMode: ModeV1},
		{name: "v1", data: makeV1SignedAPK(t), hasV1: true, verified: true, wantMode: ModeV1},
		{name: "v2", data: makeModernSignedAPK(t, false, false), hasV2: true, verified: true, wantMode: ModeV2},
		{name: "v3", data: makeModernSignedAPK(t, true, false), hasV2: true, hasV3: true, verified: true, wantMode: ModeV2},
		{name: "v31", data: makeModernSignedAPK(t, true, true), hasV2: true, hasV3: true, hasV31: true, verified: true, wantMode: ModeV2},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			detection, err := Detect(bytes.NewReader(testCase.data), int64(len(testCase.data)))
			if err != nil {
				t.Fatal(err)
			}
			if detection.Mode != testCase.wantMode || detection.HasV1 != testCase.hasV1 || detection.HasV2 != testCase.hasV2 || detection.HasV3 != testCase.hasV3 || detection.HasV31 != testCase.hasV31 || detection.Verified != testCase.verified {
				t.Fatalf("detection = %#v", detection)
			}
			if !testCase.verified && len(detection.Warnings) == 0 {
				t.Fatal("unverified fixture did not report warnings")
			}
		})
	}
}

func TestDetectV3OnlyAndMixedV1V2(t *testing.T) {
	v3 := makeModernSignedAPK(t, true, false)
	parsed, err := loadArchive(bytes.NewReader(v3), int64(len(v3)))
	if err != nil {
		t.Fatal(err)
	}
	var v3Pairs []apksigblock.Pair
	for _, pair := range parsed.block.Pairs {
		if pair.ID == apksigblock.IDV3Signature {
			v3Pairs = append(v3Pairs, pair)
		}
	}
	v3Only := replaceSigningPairs(t, v3, v3Pairs)
	detection, err := Detect(bytes.NewReader(v3Only), int64(len(v3Only)))
	if err != nil {
		t.Fatal(err)
	}
	if !detection.HasV3 || detection.HasV2 || !detection.Verified {
		t.Fatalf("V3-only detection = %#v", detection)
	}
	v1 := makeV1SignedAPK(t)
	algorithm, ok := algo.ByID(algo.SigRSAPKCS1SHA256)
	if !ok {
		t.Fatal("algorithm not found")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(6), Subject: pkix.Name{CommonName: "mixed-fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var mixed bytes.Buffer
	if err := (&apkwriter.SignedAPKWriter{Src: datasource.NewBytes(v1), Signers: []*signer.SignerConfig{{PrivateKey: key, Certs: []*x509.Certificate{certificate}, Algorithms: []algo.Algorithm{algorithm}}}}).Write(&mixed); err != nil {
		t.Fatal(err)
	}
	detection, err = Detect(bytes.NewReader(mixed.Bytes()), int64(mixed.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if !detection.HasV1 || !detection.HasV2 || detection.HasV3 || !detection.Verified || detection.Mode != ModeV2 {
		t.Fatalf("mixed detection = %#v", detection)
	}
}

func TestV3SDKRangesAreVerified(t *testing.T) {
	data := makeModernSignedAPK(t, true, true)
	result, err := apkverifier.Verify(datasource.NewBytes(data), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if result.V3 == nil || len(result.V3.Signers) != 1 || result.V3.Signers[0].MinSDK != 28 || result.V3.Signers[0].MaxSDK != 32 {
		t.Fatalf("V3 SDK range = %#v", result.V3)
	}
	if result.V31 == nil || len(result.V31.Signers) != 1 || result.V31.Signers[0].MinSDK != 33 || result.V31.Signers[0].MaxSDK != 35 {
		t.Fatalf("V3.1 SDK range = %#v", result.V31)
	}
}

func TestReadChannelPrefersModernPairOverV1Suffix(t *testing.T) {
	base := makeZIP(t, "")
	var v1 bytes.Buffer
	if err := Pack(bytes.NewReader(base), int64(len(base)), "legacy", &v1, TransformOptions{Mode: ModeV1}); err != nil {
		t.Fatal(err)
	}
	mixed := addSigningBlock(t, v1.Bytes(), []apksigblock.Pair{{ID: ChannelPairID, Value: []byte("modern")}})
	channel, err := ReadChannel(bytes.NewReader(mixed), int64(len(mixed)))
	if err != nil {
		t.Fatal(err)
	}
	if channel != "modern" {
		t.Fatalf("ReadChannel = %q, want modern", channel)
	}
}

func TestOptionalApksignerInterop(t *testing.T) {
	apksigner, err := exec.LookPath("apksigner")
	if err != nil {
		t.Skip("apksigner is not available")
	}
	input := makeModernSignedAPK(t, false, false)
	var packed bytes.Buffer
	if err := Pack(bytes.NewReader(input), int64(len(input)), "interop", &packed, TransformOptions{Mode: ModeV2, VerifyInput: true}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "interop.apk")
	if err := os.WriteFile(path, packed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(apksigner, "verify", "--verbose", path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("apksigner verify: %v\n%s", err, output)
	}
}
