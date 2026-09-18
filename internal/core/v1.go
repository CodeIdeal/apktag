package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// V1Marker terminates the VasDolly V1 ZIP comment suffix.
const V1Marker = "ltlovezh"

var v1Marker = []byte(V1Marker)

func validateChannel(channel string) ([]byte, error) {
	if channel == "" || !utf8.ValidString(channel) {
		return nil, ErrInvalidChannel
	}
	return []byte(channel), nil
}

func validateV1Channel(channel string) ([]byte, error) {
	encoded, err := validateChannel(channel)
	if err != nil {
		return nil, err
	}
	// VasDolly 3.0.6 reads the uint16 field through a signed Java short.
	// Keeping the compatibility cap makes generated packages readable by it.
	if len(encoded) > 32767 {
		return nil, fmt.Errorf("%w: UTF-8 value is %d bytes; maximum is 32767", ErrInvalidChannel, len(encoded))
	}
	return encoded, nil
}

func v1Comment(a *archive) []byte {
	start := int(a.eocd.Offset) + 22
	return a.data[start:]
}

func parseV1Comment(comment []byte) (channel string, found bool, err error) {
	if len(comment) < len(v1Marker) {
		return "", false, nil
	}
	if string(comment[len(comment)-len(v1Marker):]) != string(v1Marker) {
		return "", false, nil
	}
	if len(comment) < len(v1Marker)+2 {
		return "", false, errors.New("apktag: truncated V1 channel suffix")
	}
	lengthPos := len(comment) - len(v1Marker) - 2
	channelLen := int(binary.LittleEndian.Uint16(comment[lengthPos : lengthPos+2]))
	if channelLen <= 0 || channelLen > lengthPos {
		return "", false, errors.New("apktag: invalid V1 channel length")
	}
	channelBytes := comment[lengthPos-channelLen : lengthPos]
	if !utf8.Valid(channelBytes) {
		return "", false, errors.New("apktag: V1 channel is not valid UTF-8")
	}
	return string(channelBytes), true, nil
}

func writeV1(a *archive, channel string, logger Logger, path string) ([]byte, error) {
	channelBytes, err := validateV1Channel(channel)
	if err != nil {
		return nil, err
	}
	comment := v1Comment(a)
	if len(comment) == 0 {
		LogPrintf(logger, "file : %s , has no comment\n", path)
	} else {
		LogPrintf(logger, "file : %s , has comment\n", path)
	}
	if existing, found, err := parseV1Comment(comment); err != nil {
		return nil, err
	} else if found {
		return nil, fmt.Errorf("%w: %q", ErrChannelExists, existing)
	}
	newCommentLen := len(comment) + len(channelBytes) + 2 + len(v1Marker)
	if newCommentLen > zipMaxComment {
		return nil, errors.New("apktag: ZIP comment exceeds 65535 bytes")
	}
	newComment := make([]byte, 0, newCommentLen)
	newComment = append(newComment, comment...)
	newComment = append(newComment, channelBytes...)
	var length [2]byte
	binary.LittleEndian.PutUint16(length[:], uint16(len(channelBytes)))
	newComment = append(newComment, length[:]...)
	newComment = append(newComment, v1Marker...)

	commentStart := int(a.eocd.Offset) + 22
	out := make([]byte, commentStart+len(newComment))
	copy(out, a.data[:commentStart])
	copy(out[commentStart:], newComment)
	binary.LittleEndian.PutUint16(out[int(a.eocd.Offset)+20:int(a.eocd.Offset)+22], uint16(len(newComment)))
	return out, nil
}

func removeV1(a *archive, logger Logger, apkName string) ([]byte, error) {
	comment := v1Comment(a)
	if len(comment) == 0 {
		LogPrintf(logger, "file : %s , has no comment\n", apkName)
	} else {
		LogPrintf(logger, "file : %s , has comment\n", apkName)
	}
	_, found, err := parseV1Comment(comment)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrChannelNotFound
	}
	suffixLen := len(v1Marker) + 2 + int(binary.LittleEndian.Uint16(comment[len(comment)-len(v1Marker)-2:len(comment)-len(v1Marker)]))
	prefixLen := len(comment) - suffixLen
	commentStart := int(a.eocd.Offset) + 22
	out := make([]byte, commentStart+prefixLen)
	copy(out, a.data[:commentStart+prefixLen])
	binary.LittleEndian.PutUint16(out[int(a.eocd.Offset)+20:int(a.eocd.Offset)+22], uint16(prefixLen))
	LogPrintf(logger, "file : %s , remove comment success\n", apkName)
	return out, nil
}

func readV1(a *archive, logger Logger, path string) (string, error) {
	comment := v1Comment(a)
	if len(comment) == 0 {
		LogPrintf(logger, "file : %s , has no comment\n", path)
	} else {
		LogPrintf(logger, "file : %s , has comment\n", path)
	}
	channel, found, err := parseV1Comment(comment)
	if err != nil {
		return "", err
	}
	if !found {
		LogPrintf(logger, "APK : %s not have channel info from Zip Comment\n", path)
		return "", ErrChannelNotFound
	}
	return channel, nil
}

func writeOutput(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
