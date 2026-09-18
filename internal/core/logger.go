package core

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
)

// Logger is the interface used for logging in apktag.
type Logger interface {
	Print(v ...any)
	Printf(format string, v ...any)
	Println(v ...any)
}

type writerLogger struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *writerLogger) Print(v ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprint(l.w, v...)
}

func (l *writerLogger) Printf(format string, v ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, format, v...)
}

func (l *writerLogger) Println(v ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(l.w, v...)
}

var globalLogger atomic.Pointer[Logger]

// SetLogger sets the global logger. Passing nil disables logging.
func SetLogger(l Logger) {
	if l == nil {
		globalLogger.Store(nil)
		return
	}
	globalLogger.Store(&l)
}

// SetOutput sets the global logger to write to w. Passing nil or io.Discard disables logging.
func SetOutput(w io.Writer) {
	if w == nil || w == io.Discard {
		SetLogger(nil)
		return
	}
	SetLogger(&writerLogger{w: w})
}

// CurrentLogger returns the effective logger from opts or the global logger.
func CurrentLogger(optsLogger Logger) Logger {
	if optsLogger != nil {
		return optsLogger
	}
	if lp := globalLogger.Load(); lp != nil {
		return *lp
	}
	return nil
}

func LogPrintln(l Logger, v ...any) {
	if l != nil {
		l.Println(v...)
	}
}

func LogPrintf(l Logger, format string, v ...any) {
	if l != nil {
		l.Printf(format, v...)
	}
}

func LogPrint(l Logger, v ...any) {
	if l != nil {
		l.Print(v...)
	}
}

// FormatByteBuffer returns the Java-compatible ByteBuffer string representation.
func FormatByteBuffer(size int) string {
	return fmt.Sprintf("java.nio.HeapByteBuffer[pos=0 lim=%d cap=%d]", size, size)
}

// FormatIdValueMap returns the Java-compatible IdValueMap string representation.
func FormatIdValueMap(pairs []apksigblock.Pair) string {
	if len(pairs) == 0 {
		return "{}"
	}
	var b strings.Builder
	b.WriteString("{")
	for i, pair := range pairs {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d=%s", int32(pair.ID), FormatByteBuffer(len(pair.Value)))
	}
	b.WriteString("}")
	return b.String()
}

// FormatApkSectionInfo returns the Java-compatible ApkSectionInfo string representation.
func FormatApkSectionInfo(apkSize int64, lowMemory bool, contentSize int, signingBlockSize int, cdSize int, eocdSize int, signingBlockOffset int64, cdOffset int64, eocdOffset int64) string {
	var contentStr string
	if lowMemory {
		contentStr = "null"
	} else {
		contentStr = fmt.Sprintf("first = %s , second = 0", FormatByteBuffer(contentSize))
	}
	signingBlockStr := fmt.Sprintf("first = %s , second = %d", FormatByteBuffer(signingBlockSize), signingBlockOffset)
	cdStr := fmt.Sprintf("first = %s , second = %d", FormatByteBuffer(cdSize), cdOffset)
	eocdStr := fmt.Sprintf("first = %s , second = %d", FormatByteBuffer(eocdSize), eocdOffset)

	return fmt.Sprintf("lowMemory : %t\n apkSize : %d\n contentEntry : %s\n schemeV2Block : %s\n centralDir : %s\n eocd : %s",
		lowMemory, apkSize, contentStr, signingBlockStr, cdStr, eocdStr)
}

func readerPath(r io.ReaderAt) string {
	if nr, ok := r.(interface{ Name() string }); ok {
		return nr.Name()
	}
	return ""
}
