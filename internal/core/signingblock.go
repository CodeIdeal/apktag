package core

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
)

// ChannelPairID is the VasDolly ID-value pair identifier used in an APK
// Signing Block.
const ChannelPairID uint32 = 0x881155ff
const WallePairID uint32 = 0x71777777

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

func normalizeBlockID(id uint32) uint32 {
	if id == 0 {
		return ChannelPairID
	}
	return id
}

// ValidateBlockID rejects IDs whose values have Android-defined semantics in
// the APK Signing Block. A zero ID is valid and selects ChannelPairID.
func ValidateBlockID(id uint32) error {
	switch normalizeBlockID(id) {
	case apksigblock.IDPaddingPair,
		apksigblock.IDV2Signature,
		apksigblock.IDV3Signature,
		apksigblock.IDV31Signature,
		apksigblock.IDSourceStampV1,
		apksigblock.IDSourceStampV2,
		apksigblock.IDDependencyInfo:
		return fmt.Errorf("%w: 0x%08x", ErrReservedBlockID, id)
	default:
		return nil
	}
}

func validatePairValue(id uint32, value []byte) error {
	if len(value) == 0 {
		return errors.New("apktag: empty V2/V3 channel pair")
	}
	if !utf8.Valid(value) {
		return errors.New("apktag: V2/V3 channel is not valid UTF-8")
	}
	if id == WallePairID {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(value, &object); err != nil {
			return fmt.Errorf("apktag: invalid Walle channel JSON: %w", err)
		}
		raw, ok := object["channel"]
		var channel string
		if !ok || json.Unmarshal(raw, &channel) != nil || channel == "" {
			return errors.New("apktag: Walle channel JSON must contain a non-empty string channel")
		}
	}
	return nil
}

func channelPair(block *apksigblock.Block, id uint32) (value []byte, found bool, err error) {
	if block == nil {
		return nil, false, nil
	}
	for _, pair := range block.Pairs {
		if pair.ID != id {
			continue
		}
		if found {
			return nil, false, errors.New("apktag: duplicate V2/V3 channel pair")
		}
		if err := validatePairValue(id, pair.Value); err != nil {
			return nil, false, err
		}
		value = append([]byte(nil), pair.Value...)
		found = true
	}
	return value, found, nil
}

func writeV2(a *archive, channel string, id uint32) ([]byte, error) {
	a.log.Step("write_v2_channel")
	if err := ValidateBlockID(id); err != nil {
		return nil, err
	}
	channelBytes, err := validateChannel(channel)
	if err != nil {
		return nil, err
	}
	if a.block == nil {
		return nil, ErrNoSigningBlock
	}
	id = normalizeBlockID(id)
	if id == WallePairID {
		channelBytes, err = json.Marshal(map[string]string{"channel": channel})
		if err != nil {
			return nil, err
		}
	}
	if _, found, err := channelPair(a.block, id); err != nil {
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
				pairs = append(pairs, apksigblock.Pair{ID: id, Value: append([]byte(nil), channelBytes...)})
				inserted = true
			}
			continue
		}
		pairs = append(pairs, apksigblock.Pair{ID: pair.ID, Value: append([]byte(nil), pair.Value...)})
	}
	if !inserted {
		pairs = append(pairs, apksigblock.Pair{ID: id, Value: append([]byte(nil), channelBytes...)})
	}
	return rewriteBlock(a, pairs)
}

func removeV2(a *archive, id uint32) ([]byte, error) {
	a.log.Step("remove_v2_channel")
	if err := ValidateBlockID(id); err != nil {
		return nil, err
	}
	if a.block == nil {
		return nil, ErrNoSigningBlock
	}
	if _, _, err := parseV1Comment(v1Comment(a)); err != nil {
		return nil, err
	}
	id = normalizeBlockID(id)
	_, found, err := channelPair(a.block, id)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrChannelNotFound
	}
	pairs := make([]apksigblock.Pair, 0, len(a.block.Pairs))
	for _, pair := range a.block.Pairs {
		if pair.ID == id || pair.ID == apksigblock.IDPaddingPair {
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
			return nil, errors.New("apktag: signing block is too large")
		}
		if uint64(len(pair.Value)) > ^uint64(0)-12-bodyLen {
			return nil, errors.New("apktag: signing block is too large")
		}
		bodyLen += 12 + uint64(len(pair.Value))
	}
	const footerLen uint64 = 8 + 16
	const paddingPairLen uint64 = 12
	base := uint64(8) + bodyLen + paddingPairLen + footerLen
	padding := (4096 - base%4096) % 4096
	total := base + padding
	if total > uint64(maxInt()) || total > ^uint64(0)-8 {
		return nil, errors.New("apktag: signing block is too large")
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
		return nil, errors.New("apktag: internal signing block alignment error")
	}
	return out, nil
}

func rewriteBlock(a *archive, pairs []apksigblock.Pair) ([]byte, error) {
	a.log.Step("rewrite_signing_block")
	blockBytes, err := assembleSigningBlock(pairs)
	if err != nil {
		return nil, err
	}
	newCDOffset := a.block.StartOffset + int64(len(blockBytes))
	if newCDOffset < 0 || uint64(newCDOffset) > uint64(^uint32(0)) {
		return nil, errors.New("apktag: central directory offset exceeds ZIP limits")
	}
	a.log.Debug("signing block rebuilt", "bytes", len(blockBytes), "pairs", len(pairs), "old_cd_offset", a.eocd.CDStartOffset, "cd_offset", newCDOffset, "padding_bytes", len(blockBytes)-signingBlockUnpaddedSize(pairs))
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

func signingBlockUnpaddedSize(pairs []apksigblock.Pair) int {
	size := 8 + 24 + 12
	for _, pair := range pairs {
		size += 12 + len(pair.Value)
	}
	return size
}
