//go:build interop

package core

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
	"github.com/agusibrahim/apksig-go/pkg/apkverifier"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

// All subprocesses run in disposable directories, with a bounded log and a
// deadline. A reference process exiting zero is not evidence of success.
type interopHarness struct{ java, vas, walle, cli, apksigner string }
type interopCase struct {
	h   *interopHarness
	t   *testing.T
	dir string
	log strings.Builder
}
type interopResult struct {
	text   string
	stderr string
	err    error
}
type interopOutput struct{ bytes.Buffer }

func (b *interopOutput) Write(p []byte) (int, error) {
	n := len(p)
	left := (1 << 20) - b.Len()
	if left > 0 {
		if len(p) > left {
			p = p[:left]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func TestInterop(t *testing.T) {
	h := &interopHarness{vas: os.Getenv("VASDOLLY_JAR"), walle: os.Getenv("WALLE_JAR"), apksigner: os.Getenv("APKSIGNER")}
	var err error
	h.java, err = exec.LookPath("java")
	if err != nil {
		t.Fatal("interop requires Java on PATH")
	}
	for _, ref := range []struct{ name, path, hash string }{
		{"VasDolly 3.0.6", h.vas, "15364fd2d3725bed78d5bb4b00ce63b18e3a018438faf8fe030049099aa4da27"},
		{"Walle 1.1.6", h.walle, "e655c5284ee1fc2916ccca2ed3217c4be227a8284fdb9218308c9cf431ef222c"},
	} {
		if ref.path == "" {
			t.Fatal("interop requires VASDOLLY_JAR and WALLE_JAR")
		}
		data, e := os.ReadFile(ref.path)
		if e != nil {
			t.Fatal(e)
		}
		sum := fmt.Sprintf("%x", sha256.Sum256(data))
		if sum != ref.hash {
			t.Fatalf("%s SHA-256 %s differs from baseline %s; review expectations before upgrading", ref.name, sum, ref.hash)
		}
		t.Logf("%s SHA-256 %s", ref.name, sum)
	}
	h.vas, err = filepath.Abs(h.vas)
	if err != nil {
		t.Fatal(err)
	}
	h.walle, err = filepath.Abs(h.walle)
	if err != nil {
		t.Fatal(err)
	}
	if h.apksigner != "" {
		h.apksigner, err = exec.LookPath(h.apksigner)
		if err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	h.cli = filepath.Join(t.TempDir(), "apktag")
	if os.PathSeparator == '\\' {
		h.cli += ".exe"
	}
	c := h.newCase(t)
	c.must(c.run("go", "-C", filepath.Clean(filepath.Join(root, "../..")), "build", "-o", h.cli, "./cmd/apktag"))
	h.matrix(t)
}
func (h *interopHarness) newCase(t *testing.T) *interopCase {
	c := &interopCase{h: h, t: t, dir: t.TempDir()}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		t.Log(c.log.String())
		dest := os.Getenv("INTEROP_ARTIFACT_DIR")
		if dest == "" {
			return
		}
		dest = filepath.Join(dest, strings.NewReplacer("/", "_", "\\", "_").Replace(t.Name()))
		if e := os.MkdirAll(dest, 0755); e != nil {
			t.Error(e)
			return
		}
		files, e := os.MkdirTemp(dest, "files-")
		if e != nil {
			t.Error(e)
			return
		}
		if e = os.CopyFS(files, os.DirFS(c.dir)); e != nil {
			t.Error(e)
		}
		if e = os.WriteFile(filepath.Join(files, "commands.log"), []byte(c.log.String()), 0644); e != nil {
			t.Error(e)
		}
		t.Logf("failure artifacts: %s", files)
	})
	return c
}
func (c *interopCase) run(args ...string) interopResult {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = c.dir
	cmd.WaitDelay = time.Second
	var stdout, stderr interopOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	printable := append([]string(nil), args...)
	for i, s := range printable {
		if len(s) > 200 {
			printable[i] = fmt.Sprintf("%s…[%d bytes]", s[:100], len(s))
		}
	}
	fmt.Fprintf(&c.log, "args=%q\nexit=%v\nstdout:\n%s\nstderr:\n%s\n", printable, err, stdout.String(), stderr.String())
	if ctx.Err() != nil {
		c.t.Fatalf("process timed out: %q", printable)
	}
	return interopResult{text: stdout.String(), stderr: stderr.String(), err: err}
}
func (c *interopCase) must(r interopResult) string {
	c.t.Helper()
	if r.err != nil {
		c.t.Fatalf("command failed: %v\n%s", r.err, r.text+r.stderr)
	}
	return r.text
}
func (c *interopCase) jar(tool string, args ...string) interopResult {
	jar := c.h.vas
	if tool == "walle" {
		jar = c.h.walle
	}
	return c.run(append([]string{c.h.java, "-Dfile.encoding=UTF-8", "-jar", jar}, args...)...)
}
func (c *interopCase) app(args ...string) interopResult {
	return c.run(append([]string{c.h.cli}, args...)...)
}
func (c *interopCase) write(name string, data []byte) string {
	c.t.Helper()
	p := filepath.Join(c.dir, name)
	if e := os.WriteFile(p, data, 0644); e != nil {
		c.t.Fatal(e)
	}
	return p
}
func (c *interopCase) read(path string) []byte {
	c.t.Helper()
	data, e := os.ReadFile(path)
	if e != nil {
		c.t.Fatal(e)
	}
	return data
}
func interopID(tool string) uint32 {
	if tool == "walle" {
		return WallePairID
	}
	return ChannelPairID
}
func interopFormat(tool string) string {
	if tool == "walle" {
		return "Walle"
	}
	return "VasDolly"
}
func (c *interopCase) put(tool, ch, base, out string) interopResult {
	if strings.HasPrefix(tool, "app-") {
		return c.app("put", "-c", ch, "--block-id", interopFormat(strings.TrimPrefix(tool, "app-")), "--out", out, base)
	}
	// VasDolly mkdirs a nonexistent output even when its name ends in .apk.
	// Precreate an empty output file to select its documented single-file mode.
	if tool == "vas" && strings.HasSuffix(out, ".apk") {
		if e := os.WriteFile(out, nil, 0644); e != nil {
			c.t.Fatal(e)
		}
	}
	return c.jar(tool, "put", "-c", ch, base, out)
}
func (c *interopCase) appRead(path, tool string) interopResult {
	return c.app("get", "--block-id", interopFormat(tool), "-c", path)
}
func (c *interopCase) jarRead(path, tool string) interopResult {
	if tool == "vas" {
		return c.jar(tool, "get", "-c", path)
	}
	return c.jar(tool, "show", "-c", path)
}
func (c *interopCase) jarValue(path, tool string) string {
	c.t.Helper()
	s := c.must(c.jarRead(path, tool))
	if tool == "vas" {
		i := strings.LastIndex(s, "Channel: ")
		j := strings.LastIndex(s, ",len=")
		if i < 0 || j < i {
			c.t.Fatalf("unrecognized VasDolly output %q", s)
		}
		return s[i+len("Channel: ") : j]
	}
	prefix := path + " : "
	i := strings.LastIndex(s, prefix)
	if i < 0 {
		c.t.Fatalf("unrecognized Walle output %q", s)
	}
	return strings.TrimSuffix(strings.TrimSuffix(s[i+len(prefix):], "\n"), "\r")
}
func (c *interopCase) checkRead(path, tool, want string) {
	c.t.Helper()
	if got := c.must(c.appRead(path, tool)); got != want+"\n" {
		c.t.Fatalf("apktag channel %q want %q", got, want)
	}
	if got := c.jarValue(path, tool); got != want {
		c.t.Fatalf("%s channel %q want %q", tool, got, want)
	}
}
func (c *interopCase) absent(path, tool string) {
	c.t.Helper()
	r := c.appRead(path, tool)
	if r.err == nil || !strings.Contains(r.text+r.stderr, "channel not found") {
		c.t.Fatalf("expected absent channel: %+v", r)
	}
	if got := c.jarValue(path, tool); got != "" {
		c.t.Fatalf("expected empty %s channel, got %q", tool, got)
	}
}
func interopArchive(t *testing.T, data []byte) *archive {
	t.Helper()
	a, e := loadArchive(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func (c *interopCase) verify(path string, base []byte) {
	c.t.Helper()
	before, e := apkverifier.Verify(datasource.NewBytes(base), 0, 0)
	if e != nil {
		c.t.Fatal(e)
	}
	after, e := apkverifier.Verify(datasource.NewBytes(c.read(path)), 0, 0)
	if e != nil {
		c.t.Fatal(e)
	}
	want := []bool{before.V1Verified, before.V2Verified, before.V3Verified, before.V31Verified}
	got := []bool{after.V1Verified, after.V2Verified, after.V3Verified, after.V31Verified}
	if !before.Verified || !after.Verified || !reflect.DeepEqual(want, got) {
		c.t.Fatalf("signature verification before=%v after=%v errors=%v", want, got, after.Errors)
	}
	if c.h.apksigner != "" {
		c.must(c.run(c.h.apksigner, "verify", "--verbose", path))
	}
}

// Remove only padding and derived offsets. Non-target pair order and bytes,
// compressed file contents, CD and EOCD/comment must otherwise be unchanged.
func interopCanonical(t *testing.T, data []byte, ignore uint32) []byte {
	a := interopArchive(t, data)
	if a.block == nil {
		return data
	}
	var out bytes.Buffer
	out.Write(a.data[:a.block.StartOffset])
	for _, p := range a.block.Pairs {
		if p.ID == apksigblock.IDPaddingPair || p.ID == ignore {
			continue
		}
		value := p.Value
		if p.ID == WallePairID {
			var object any
			if e := json.Unmarshal(value, &object); e != nil {
				t.Fatal(e)
			}
			value, _ = json.Marshal(object)
		}
		_ = binary.Write(&out, binary.LittleEndian, p.ID)
		_ = binary.Write(&out, binary.LittleEndian, uint64(len(value)))
		out.Write(value)
	}
	tail := append([]byte(nil), a.data[a.eocd.CDStartOffset:]...)
	off := a.eocd.Offset - a.eocd.CDStartOffset
	binary.LittleEndian.PutUint32(tail[off+16:off+20], 0)
	out.Write(tail)
	return out.Bytes()
}
func (c *interopCase) compare(a, b []byte, ignore uint32, exact bool) {
	c.t.Helper()
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	fmt.Fprintf(&c.log, "MD5 %x / %x; lengths %d/%d; first byte difference %d\n", md5.Sum(a), md5.Sum(b), len(a), len(b), i)
	aa, bb := a, b
	if !exact {
		aa = interopCanonical(c.t, a, ignore)
		bb = interopCanonical(c.t, b, ignore)
	}
	if !bytes.Equal(aa, bb) {
		c.t.Fatalf("unexpected structure/byte difference MD5 %x / %x; first byte %d; canonical sizes %d/%d", md5.Sum(a), md5.Sum(b), i, len(aa), len(bb))
	}
}
func (c *interopCase) roundTrip(base []byte, tool, ch string) {
	c.t.Helper()
	appBase := c.write("app-base.apk", base)
	jarBase := c.write("jar-base.apk", base)
	app := filepath.Join(c.dir, "app.apk")
	jar := filepath.Join(c.dir, "jar.apk")
	c.must(c.put("app-"+tool, ch, appBase, app))
	c.must(c.put(tool, ch, jarBase, jar))
	c.checkRead(app, tool, ch)
	c.checkRead(jar, tool, ch)
	c.compare(c.read(app), c.read(jar), 0, false)
	for _, p := range []string{app, jar} {
		c.verify(p, base)
		c.compare(base, c.read(p), interopID(tool), false)
	}
	clean := filepath.Join(c.dir, "clean.apk")
	c.must(c.app("remove", "--block-id", interopFormat(tool), jar, clean))
	c.absent(clean, tool)
	c.verify(clean, base)
	c.compare(base, c.read(clean), 0, false)
	if tool == "vas" {
		c.must(c.jar(tool, "remove", "-c", app))
	} else {
		c.must(c.jar(tool, "rm", app))
	}
	c.absent(app, tool)
	c.verify(app, base)
	c.compare(base, c.read(app), 0, false)
	c.compare(base, c.read(appBase), 0, true)
	c.compare(base, c.read(jarBase), 0, true)
}
