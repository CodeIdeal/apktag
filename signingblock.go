package vasdolly

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"

	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
)

// ChannelPairID is the VasDolly ID-value pair identifier used in an APK
// Signing Block.
const ChannelPairID uint32 = 0x881155ff

const channelPairID = ChannelPairID

func modernPair(blockPairs []apksigblock.Pair) (hasV2, hasV3 bool) {
	for _, pair := range blockPairs {
		switch pair.ID {
		case apksigblock.IDV2Signature:
			hasV2 = true
		case apksigblock.IDV3Signature, apksigblock.IDV31Signature:
			hasV3 = true
		}
	}
	return hasV2, hasV3
}

func channelPair(block *apksigblock.Block) (value []byte, found bool, err error) {
	if block == nil {
		return nil, false, nil
	}
	for _, pair := range block.Pairs {
		if pair.ID != channelPairID {
			continue
		}
		if found {
			return nil, false, errors.New("vasdolly: duplicate V2/V3 channel pair")
		}
		if len(pair.Value) == 0 {
			return nil, false, errors.New("vasdolly: empty V2/V3 channel pair")
		}
		if !utf8.Valid(pair.Value) {
			return nil, false, errors.New("vasdolly: V2/V3 channel is not valid UTF-8")
		}
		value = append([]byte(nil), pair.Value...)
		found = true
	}
	return value, found, nil
}

func writeV2(a *archive, channel string) ([]byte, error) {
	channelBytes, err := validateChannel(channel)
	if err != nil {
		return nil, err
	}
	if a.block == nil {
		return nil, ErrNoSigningBlock
	}
	if _, found, err := channelPair(a.block); err != nil {
		return nil, err
	} else if found {
		return nil, ErrChannelExists
	}
	if _, found, err := parseV1Comment(v1Comment(a)); err != nil {
		return nil, err
	} else if found {
		return nil, ErrChannelExists
	}
	pairs := make([]apksigblock.Pair, 0, len(a.block.Pairs)+1)
	inserted := false
	for _, pair := range a.block.Pairs {
		if pair.ID == apksigblock.IDPaddingPair {
			if !inserted {
				pairs = append(pairs, apksigblock.Pair{ID: channelPairID, Value: append([]byte(nil), channelBytes...)})
				inserted = true
			}
			continue
		}
		pairs = append(pairs, apksigblock.Pair{ID: pair.ID, Value: append([]byte(nil), pair.Value...)})
	}
	if !inserted {
		pairs = append(pairs, apksigblock.Pair{ID: channelPairID, Value: append([]byte(nil), channelBytes...)})
	}
	return rewriteBlock(a, pairs)
}

func removeV2(a *archive) ([]byte, error) {
	if a.block == nil {
		return nil, ErrNoSigningBlock
	}
	if _, _, err := parseV1Comment(v1Comment(a)); err != nil {
		return nil, err
	}
	_, found, err := channelPair(a.block)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrChannelNotFound
	}
	pairs := make([]apksigblock.Pair, 0, len(a.block.Pairs))
	for _, pair := range a.block.Pairs {
		if pair.ID == channelPairID || pair.ID == apksigblock.IDPaddingPair {
			continue
		}
		pairs = append(pairs, apksigblock.Pair{ID: pair.ID, Value: append([]byte(nil), pair.Value...)})
	}
	return rewriteBlock(a, pairs)
}

func assembleSigningBlock(pairs []apksigblock.Pair) ([]byte, error) {
	var bodyLen uint64
	for _, pair := range pairs {
		if bodyLen > ^uint64(0)-12 {
			return nil, errors.New("vasdolly: signing block is too large")
		}
		if uint64(len(pair.Value)) > ^uint64(0)-12-bodyLen {
			return nil, errors.New("vasdolly: signing block is too large")
		}
		bodyLen += 12 + uint64(len(pair.Value))
	}
	const footerLen uint64 = 8 + 16
	const paddingPairLen uint64 = 12
	base := uint64(8) + bodyLen + paddingPairLen + footerLen
	padding := (4096 - base%4096) % 4096
	total := base + padding
	if total > uint64(maxInt()) || total > ^uint64(0)-8 {
		return nil, errors.New("vasdolly: signing block is too large")
	}
	body := make([]byte, 0, int(bodyLen+paddingPairLen+padding))
	for _, pair := range pairs {
		var length [8]byte
		binary.LittleEndian.PutUint64(length[:], uint64(4+len(pair.Value)))
		body = append(body, length[:]...)
		var id [4]byte
		binary.LittleEndian.PutUint32(id[:], pair.ID)
		body = append(body, id[:]...)
		body = append(body, pair.Value...)
	}
	var length [8]byte
	binary.LittleEndian.PutUint64(length[:], uint64(4)+padding)
	body = append(body, length[:]...)
	var paddingID [4]byte
	binary.LittleEndian.PutUint32(paddingID[:], apksigblock.IDPaddingPair)
	body = append(body, paddingID[:]...)
	body = append(body, make([]byte, padding)...)
	blockSize := uint64(len(body)) + footerLen
	out := make([]byte, 0, 8+len(body)+int(footerLen))
	binary.LittleEndian.PutUint64(length[:], blockSize)
	out = append(out, length[:]...)
	out = append(out, body...)
	out = append(out, length[:]...)
	out = append(out, []byte(zipSigMagic)...)
	if len(out)%4096 != 0 {
		return nil, errors.New("vasdolly: internal signing block alignment error")
	}
	return out, nil
}

func rewriteBlock(a *archive, pairs []apksigblock.Pair) ([]byte, error) {
	blockBytes, err := assembleSigningBlock(pairs)
	if err != nil {
		return nil, err
	}
	newCDOffset := a.block.StartOffset + int64(len(blockBytes))
	if newCDOffset < 0 || uint64(newCDOffset) > uint64(^uint32(0)) {
		return nil, errors.New("vasdolly: central directory offset exceeds ZIP limits")
	}
	cdStart := int(a.eocd.CDStartOffset)
	cdEnd := cdStart + int(a.eocd.CDSize)
	eocd := append([]byte(nil), a.data[int(a.eocd.Offset):]...)
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(newCDOffset))
	out := make([]byte, 0, int(a.block.StartOffset)+len(blockBytes)+len(a.data)-cdStart)
	out = append(out, a.data[:int(a.block.StartOffset)]...)
	out = append(out, blockBytes...)
	out = append(out, a.data[cdStart:cdEnd]...)
	out = append(out, eocd...)
	return out, nil
}
