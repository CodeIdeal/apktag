package vasdolly

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
	"github.com/agusibrahim/apksig-go/pkg/apkverifier"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

const (
	zipEOCDMinSize = 22
	zipMaxComment  = 0xffff
	zip64Locator   = 0x07064b50
	zip64EOCD      = 0x06064b50
	zipSigMagic    = "APK Sig Block 42"
)

type archive struct {
	data    []byte
	ds      datasource.DataSource
	eocd    *zippkg.EOCD
	block   *apksigblock.Block
	entries []zippkg.CDEntry
}

func loadArchive(r io.ReaderAt, size int64) (*archive, error) {
	if r == nil {
		return nil, errors.New("vasdolly: nil ReaderAt")
	}
	if size < zipEOCDMinSize {
		return nil, fmt.Errorf("vasdolly: invalid APK size %d", size)
	}
	if uint64(size) > uint64(maxInt()) {
		return nil, fmt.Errorf("vasdolly: APK too large: %d", size)
	}
	ds := datasource.NewReaderAt(r, size)
	eocd, err := zippkg.FindEOCD(ds)
	if err != nil {
		return nil, fmt.Errorf("vasdolly: find EOCD: %w", err)
	}
	if err := validateEOCD(ds, eocd, size); err != nil {
		return nil, err
	}
	entries, err := zippkg.ParseCD(ds, eocd)
	if err != nil {
		return nil, fmt.Errorf("vasdolly: parse central directory: %w", err)
	}
	if err := validateEntries(ds, eocd, entries); err != nil {
		return nil, err
	}

	block, blockErr := apksigblock.Find(ds, eocd)
	if blockErr != nil {
		if signingFooterPresent(ds, eocd) || signingBlockCandidatePresent(ds, eocd) {
			return nil, fmt.Errorf("vasdolly: malformed APK Signing Block: %w", blockErr)
		}
		block = nil
	}
	if block != nil {
		if err := validateBlock(ds, eocd, block); err != nil {
			return nil, err
		}
		for _, entry := range entries {
			dataOffset, entryErr := zippkg.EntryDataOffset(ds, &entry)
			if entryErr != nil {
				return nil, fmt.Errorf("vasdolly: entry %q: %w", entry.Name, entryErr)
			}
			if dataOffset+int64(entry.CompressedSize) > block.StartOffset {
				return nil, fmt.Errorf("vasdolly: entry %q overlaps APK Signing Block", entry.Name)
			}
		}
	}
	data, err := datasource.ReadAll(ds)
	if err != nil {
		return nil, fmt.Errorf("vasdolly: read APK: %w", err)
	}
	return &archive{data: data, ds: datasource.NewBytes(data), eocd: eocd, block: block, entries: entries}, nil
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

func validateEOCD(ds datasource.DataSource, eocd *zippkg.EOCD, size int64) error {
	if eocd == nil || len(eocd.Bytes) < zipEOCDMinSize {
		return errors.New("vasdolly: malformed EOCD")
	}
	if eocd.Offset < 0 || eocd.Offset+int64(len(eocd.Bytes)) != size {
		return errors.New("vasdolly: EOCD does not terminate at EOF")
	}
	if eocd.CDStartOffset < 0 || eocd.CDSize < 0 || eocd.CDStartOffset > eocd.Offset || eocd.CDSize > eocd.Offset-eocd.CDStartOffset {
		return errors.New("vasdolly: central directory is outside APK")
	}
	if eocd.CDStartOffset+eocd.CDSize != eocd.Offset {
		return errors.New("vasdolly: central directory is not adjacent to EOCD")
	}
	if binary.LittleEndian.Uint16(eocd.Bytes[4:6]) != 0 || binary.LittleEndian.Uint16(eocd.Bytes[6:8]) != 0 || binary.LittleEndian.Uint16(eocd.Bytes[8:10]) != binary.LittleEndian.Uint16(eocd.Bytes[10:12]) {
		return errors.New("vasdolly: multi-disk ZIP is unsupported")
	}
	if binary.LittleEndian.Uint16(eocd.Bytes[8:10]) == ^uint16(0) || binary.LittleEndian.Uint32(eocd.Bytes[12:16]) == ^uint32(0) || binary.LittleEndian.Uint32(eocd.Bytes[16:20]) == ^uint32(0) {
		return errors.New("vasdolly: ZIP64 APK is unsupported")
	}
	if eocd.Offset >= 20 {
		var locator [4]byte
		if _, err := ds.ReadAt(locator[:], eocd.Offset-20); err == nil && binary.LittleEndian.Uint32(locator[:]) == zip64Locator {
			return errors.New("vasdolly: ZIP64 APK is unsupported")
		}
	}
	if eocd.Offset >= 56 {
		var marker [4]byte
		if _, err := ds.ReadAt(marker[:], eocd.Offset-56); err == nil && binary.LittleEndian.Uint32(marker[:]) == zip64EOCD {
			return errors.New("vasdolly: ZIP64 APK is unsupported")
		}
	}
	return nil
}

func validateEntries(ds datasource.DataSource, eocd *zippkg.EOCD, entries []zippkg.CDEntry) error {
	var totalCD int64
	for i := range entries {
		entry := &entries[i]
		if entry.HeaderSize < 46 || entry.LFHOffset < 0 || entry.LFHOffset >= eocd.CDStartOffset {
			return fmt.Errorf("vasdolly: central directory entry %d has invalid offset", i)
		}
		if totalCD > eocd.CDSize-entry.HeaderSize {
			return fmt.Errorf("vasdolly: central directory entry %d overflows", i)
		}
		totalCD += entry.HeaderSize
		dataOff, err := zippkg.EntryDataOffset(ds, entry)
		if err != nil {
			return fmt.Errorf("vasdolly: entry %q: %w", entry.Name, err)
		}
		if dataOff < 0 || dataOff > ds.Size() || uint64(entry.CompressedSize) > uint64(ds.Size()-dataOff) {
			return fmt.Errorf("vasdolly: entry %q data is outside APK", entry.Name)
		}
		if dataOff+int64(entry.CompressedSize) > eocd.CDStartOffset {
			return fmt.Errorf("vasdolly: entry %q overlaps central directory", entry.Name)
		}
	}
	if totalCD != eocd.CDSize {
		return fmt.Errorf("vasdolly: central directory has %d trailing bytes", eocd.CDSize-totalCD)
	}
	if len(entries) == 0 && eocd.CDSize != 0 {
		return errors.New("vasdolly: non-empty central directory has no entries")
	}
	return nil
}

func signingFooterPresent(ds datasource.DataSource, eocd *zippkg.EOCD) bool {
	if eocd == nil || eocd.CDStartOffset < 24 {
		return false
	}
	footer := make([]byte, 16)
	if _, err := ds.ReadAt(footer, eocd.CDStartOffset-16); err != nil {
		return false
	}
	return bytes.Equal(footer, []byte(zipSigMagic))
}

func signingBlockCandidatePresent(ds datasource.DataSource, eocd *zippkg.EOCD) bool {
	if eocd == nil || eocd.CDStartOffset < 24 {
		return false
	}
	footer := make([]byte, 24)
	if _, err := ds.ReadAt(footer, eocd.CDStartOffset-24); err != nil {
		return false
	}
	blockSize := binary.LittleEndian.Uint64(footer[:8])
	if blockSize < 24 || blockSize > uint64(eocd.CDStartOffset-8) {
		return false
	}
	start := eocd.CDStartOffset - int64(blockSize) - 8
	if start < 0 {
		return false
	}
	leading := make([]byte, 8)
	if _, err := ds.ReadAt(leading, start); err != nil {
		return false
	}
	return binary.LittleEndian.Uint64(leading) == blockSize
}

func validateBlock(ds datasource.DataSource, eocd *zippkg.EOCD, block *apksigblock.Block) error {
	if block.StartOffset < 0 || block.StartOffset > eocd.CDStartOffset || block.CDOffset != eocd.CDStartOffset {
		return errors.New("vasdolly: APK Signing Block has invalid offsets")
	}
	if block.StartOffset > ds.Size()-8 {
		return errors.New("vasdolly: APK Signing Block starts outside APK")
	}
	seenPadding := false
	seenKnown := make(map[uint32]bool)
	for _, pair := range block.Pairs {
		if pair.ID == apksigblock.IDPaddingPair {
			if seenPadding {
				return errors.New("vasdolly: duplicate APK Signing Block padding pair")
			}
			if len(pair.Value) > 0 {
				for _, value := range pair.Value {
					if value != 0 {
						return errors.New("vasdolly: APK Signing Block padding is not zero-filled")
					}
				}
			}
			seenPadding = true
		}
		switch pair.ID {
		case apksigblock.IDV2Signature, apksigblock.IDV3Signature, apksigblock.IDV31Signature,
			apksigblock.IDSourceStampV1, apksigblock.IDSourceStampV2, apksigblock.IDDependencyInfo, channelPairID:
			if seenKnown[pair.ID] {
				return fmt.Errorf("vasdolly: duplicate APK Signing Block pair 0x%08x", pair.ID)
			}
			seenKnown[pair.ID] = true
		}
	}
	return nil
}

func verifyArchive(a *archive) (*apkverifier.Result, error) {
	res, err := apkverifier.Verify(a.ds, 0, 0)
	if err != nil {
		return res, err
	}
	return res, nil
}
