package vasdolly_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"testing"

	vasdolly "github.com/CodeIdeal/VasDolly-go"
)

func TestPublicFacadeV1RoundTrip(t *testing.T) {
	input := makeTestAPK(t)

	var packed bytes.Buffer
	if err := vasdolly.Pack(bytes.NewReader(input), int64(len(input)), "huawei", &packed, vasdolly.TransformOptions{Mode: vasdolly.ModeV1}); err != nil {
		t.Fatal(err)
	}
	channel, err := vasdolly.ReadChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()))
	if err != nil || channel != "huawei" {
		t.Fatalf("ReadChannel = %q, %v", channel, err)
	}

	var restored bytes.Buffer
	if err := vasdolly.RemoveChannel(bytes.NewReader(packed.Bytes()), int64(packed.Len()), &restored, vasdolly.TransformOptions{Mode: vasdolly.ModeV1}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Bytes(), input) {
		t.Fatal("RemoveChannel did not restore the input APK")
	}
	if _, err := vasdolly.ReadChannel(bytes.NewReader(input), int64(len(input))); !errors.Is(err, vasdolly.ErrChannelNotFound) {
		t.Fatalf("ReadChannel error = %v, want ErrChannelNotFound", err)
	}
}

func makeTestAPK(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	entry, err := writer.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("test fixture")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
