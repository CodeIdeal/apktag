//go:build interop

package core

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
	"github.com/agusibrahim/apksig-go/pkg/apkwriter"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/signer"
)

func interopSigned(t *testing.T, base []byte, v3, v31 bool) []byte {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "interop test only"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	algorithm, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	w := &apkwriter.SignedAPKWriter{Src: datasource.NewBytes(base), Signers: []*signer.SignerConfig{{PrivateKey: key, Certs: []*x509.Certificate{cert}, Algorithms: []algo.Algorithm{algorithm}}}}
	if v3 {
		w.V3MinSdk = 28
		w.V3MaxSdk = 0x7fffffff
	}
	if v31 {
		w.V31MinSdk = 33
		w.V31MaxSdk = 0x7fffffff
	}
	var out bytes.Buffer
	if e := w.Write(&out); e != nil {
		t.Fatal(e)
	}
	return out.Bytes()
}
func interopPairs(t *testing.T, data []byte) []apksigblock.Pair {
	t.Helper()
	a := interopArchive(t, data)
	var pairs []apksigblock.Pair
	for _, p := range a.block.Pairs {
		if p.ID != apksigblock.IDPaddingPair {
			pairs = append(pairs, p)
		}
	}
	return pairs
}
func (h *interopHarness) matrix(t *testing.T) {
	v1 := makeV1SignedAPK(t)
	zip := makeZIP(t, "")
	v2 := interopSigned(t, zip, false, false)
	v23 := interopSigned(t, zip, true, false)
	var v3pairs []apksigblock.Pair
	for _, p := range interopPairs(t, v23) {
		if p.ID == apksigblock.IDV3Signature {
			v3pairs = append(v3pairs, p)
		}
	}
	fixtures := []struct {
		name string
		data []byte
	}{{"v2", v2}, {"v3only", replaceSigningPairs(t, v23, v3pairs)}, {"v1v2", interopSigned(t, v1, false, false)}, {"v2v3", v23}, {"v1v2v3", interopSigned(t, v1, true, false)}, {"v31", interopSigned(t, zip, true, true)}}
	for _, f := range fixtures {
		for _, tool := range []string{"vas", "walle"} {
			t.Run("signatures/"+f.name+"/"+tool, func(t *testing.T) {
				if (f.name == "v3only" && tool == "walle") || (f.name == "v31" && tool == "vas") {
					t.Skip("reference CLI does not support this signature layout")
				}
				h.newCase(t).roundTrip(f.data, tool, "alpha")
			})
		}
	}
	for _, ch := range []struct{ name, value string }{{"ascii", "huawei"}, {"chinese", "应用市场"}, {"emoji", "store🚀"}, {"single", "x"}, {"space", "app store"}, {"quote", `a"b`}, {"backslash", `a\b`}, {"html", "<>&"}} {
		for _, tool := range []string{"vas", "walle"} {
			t.Run("channels/"+ch.name+"/"+tool, func(t *testing.T) {
				c := h.newCase(t)
				if ch.name == "backslash" {
					src := c.write("base.apk", v2)
					c.reject(src, tool, ch.value)
					out := filepath.Join(c.dir, "jar.apk")
					c.must(c.put(tool, ch.value, src, out))
					c.checkRead(out, tool, ch.value)
					c.verify(out, v2)
					return
				}
				c.roundTrip(v2, tool, ch.value)
			})
		}
	}
	h.v1Cases(t, v1)
	h.blockCases(t, v2)
	h.inputCases(t, v2)
	h.metadataCases(t, v2)
	h.badCases(t, v1, v2, fixtures[2].data)
}
func (c *interopCase) reject(base, tool, ch string, extra ...string) {
	c.t.Helper()
	out := c.write("protected.apk", []byte("sentinel"))
	before := c.read(base)
	args := []string{"put", "-c", ch, "--block-id", interopFormat(tool), "--overwrite", "--out", out}
	args = append(args, extra...)
	args = append(args, base)
	r := c.app(args...)
	if r.err == nil {
		c.t.Fatalf("invalid input accepted: %s", r.text)
	}
	if string(c.read(out)) != "sentinel" {
		c.t.Fatal("rejected write clobbered destination")
	}
	c.compare(before, c.read(base), 0, true)
}
func interopComment(t *testing.T, base []byte, comment string) []byte {
	a := interopArchive(t, base)
	b := append([]byte(nil), base[:a.eocd.Offset+22]...)
	binary.LittleEndian.PutUint16(b[a.eocd.Offset+20:], uint16(len(comment)))
	return append(b, []byte(comment)...)
}

// This exact JAR has a CLI V1 bug: empty string is mistaken for an existing
// channel, and get does not fall back from an empty V2 result to its V1 reader.
// Do not silently turn that limitation into a passing interoperability claim.
func (h *interopHarness) v1Cases(t *testing.T, base []byte) {
	cases := []struct {
		name, ch, comment string
		valid             bool
	}{{"ascii", "alpha", "", true}, {"chinese", "渠道", "", true}, {"emoji", "🚀", "", true}, {"existing_comment", "alpha", "original-comment", true}, {"32766", strings.Repeat("a", 32766), "", true}, {"32767", strings.Repeat("a", 32767), "", true}, {"32768", strings.Repeat("a", 32768), "", false}, {"utf8_32767", strings.Repeat("界", 10922) + "a", "", true}, {"utf8_32768", strings.Repeat("界", 10922) + "ab", "", false}, {"comment65534", "x", strings.Repeat("c", 65523), true}, {"comment65535", "x", strings.Repeat("c", 65524), true}, {"comment65536", "x", strings.Repeat("c", 65525), false}}
	for _, tc := range cases {
		t.Run("v1/"+tc.name, func(t *testing.T) {
			c := h.newCase(t)
			data := interopComment(t, base, tc.comment)
			src := c.write("base.apk", data)
			jar := filepath.Join(c.dir, "jar.apk")
			r := c.put("vas", tc.ch, src, jar)
			c.must(r)
			if !strings.Contains(r.text, "only ignore") {
				t.Fatalf("expected VasDolly V1 writer limitation: %s", r.text)
			}
			if len(c.read(jar)) != 0 {
				t.Fatal("VasDolly V1 unexpectedly wrote an APK")
			}
			if !tc.valid {
				c.reject(src, "vas", tc.ch)
				return
			}
			app := filepath.Join(c.dir, "app.apk")
			c.must(c.put("app-vas", tc.ch, src, app))
			if got := c.must(c.appRead(app, "vas")); got != tc.ch+"\n" {
				t.Fatal("V1 read mismatch")
			}
			if got := c.jarValue(app, "vas"); got != "" {
				t.Fatalf("VasDolly CLI V1 read changed: %q", got)
			}
			c.verify(app, data)
			// Independently build the specified V1 suffix. No production writer is used
			// to compute this byte oracle; JAR-vs-app MD5 is unavailable for this CLI.
			comment := append([]byte(tc.comment), []byte(tc.ch)...)
			comment = binary.LittleEndian.AppendUint16(comment, uint16(len(tc.ch)))
			comment = append(comment, []byte("ltlovezh")...)
			expected := interopComment(t, base, string(comment))
			c.compare(expected, c.read(app), 0, true)
			clean := filepath.Join(c.dir, "clean.apk")
			c.must(c.app("remove", app, clean))
			c.compare(data, c.read(clean), 0, true)
			c.verify(clean, data)
			c.must(c.jar("vas", "remove", "-c", app))
			c.compare(interopComment(t, base, ""), c.read(app), 0, true)
			c.verify(app, data)
			c.compare(data, c.read(src), 0, true)
		})
	}
	t.Run("capability/walle_v1", func(t *testing.T) {
		c := h.newCase(t)
		src := c.write("base.apk", base)
		out := filepath.Join(c.dir, "out.apk")
		r := c.jar("walle", "put", "-c", "alpha", src, out)
		c.must(r)
		if !strings.Contains(r.text, "SignatureNotFoundException") {
			t.Fatalf("Walle V1 unsupported result: %s", r.text)
		}
		c.compare(base, c.read(out), 0, true)
	})
}
func (h *interopHarness) blockCases(t *testing.T, base []byte) {
	size := 32
	for _, p := range interopPairs(t, base) {
		size += 12 + len(p.Value)
	}
	for _, tool := range []string{"vas", "walle"} {
		overhead := 12
		if tool == "walle" {
			overhead += len(`{"channel":""}`)
		}
		n := 4096 - (size+overhead)%4096
		for _, delta := range []int{-1, 0, 1} {
			t.Run(fmt.Sprintf("boundary/block/%s/%+d", tool, delta), func(t *testing.T) { h.newCase(t).roundTrip(base, tool, strings.Repeat("a", n+delta)) })
		}
		t.Run("boundary/modern32768/"+tool, func(t *testing.T) { h.newCase(t).roundTrip(base, tool, strings.Repeat("a", 32768)) })
	}
}
func (h *interopHarness) inputCases(t *testing.T, base []byte) {
	for _, tool := range []string{"vas", "walle"} {
		for _, ch := range []string{"", "   "} {
			t.Run(fmt.Sprintf("input/empty/%s/%d", tool, len(ch)), func(t *testing.T) {
				c := h.newCase(t)
				src := c.write("base.apk", base)
				c.reject(src, tool, ch)
				out := filepath.Join(c.dir, "jar.apk")
				r := c.put(tool, ch, src, out)
				c.must(r)
				t.Logf("reference result: %s", r.text)
			})
		}
		t.Run("input/trim/"+tool, func(t *testing.T) {
			c := h.newCase(t)
			src := c.write("base.apk", base)
			app := filepath.Join(c.dir, "app.apk")
			c.must(c.put("app-"+tool, " alpha ", src, app))
			c.checkRead(app, tool, "alpha")
			jar := filepath.Join(c.dir, "jar.apk")
			c.must(c.put(tool, " alpha ", src, jar))
			want := "alpha\n"

			if got := c.must(c.appRead(jar, tool)); got != want {
				t.Fatalf("trim got=%q want=%q", got, want)
			}
		})
		for _, ch := range []string{"alpha", "beta"} {
			t.Run("input/duplicate/"+tool+"/"+ch, func(t *testing.T) {
				c := h.newCase(t)
				src := c.write("base.apk", base)
				first := filepath.Join(c.dir, "first.apk")
				c.must(c.put("app-"+tool, "alpha", src, first))
				c.reject(first, tool, ch)
				jar := filepath.Join(c.dir, "jar.apk")
				r := c.put(tool, ch, first, jar)
				c.must(r)
				t.Logf("duplicate reference: %s", r.text)
			})
		}
		t.Run("input/remove_absent/"+tool, func(t *testing.T) {
			c := h.newCase(t)
			src := c.write("base.apk", base)
			out := c.write("protected.apk", []byte("sentinel"))
			if r := c.app("remove", "--block-id", interopFormat(tool), src, out); r.err == nil {
				t.Fatal("absent removal succeeded")
			}
			if string(c.read(out)) != "sentinel" {
				t.Fatal("remove clobbered output")
			}
			if tool == "vas" {
				c.must(c.jar(tool, "remove", "-c", src))
			} else {
				c.must(c.jar(tool, "rm", src))
			}
			c.compare(base, c.read(src), 0, false)
		})
	}
	for _, tc := range []struct{ name, value string }{{"comma", "alpha,beta"}, {"lf", "alpha\nbeta\n"}, {"crlf", "alpha\r\nbeta\r\n"}, {"bom", "\ufeffalpha\nbeta\n"}, {"duplicates", "alpha\nalpha\nbeta\n"}} {
		for _, tool := range []string{"vas", "walle"} {
			t.Run("batch/"+tc.name+"/"+tool, func(t *testing.T) {
				c := h.newCase(t)
				src := c.write("base.apk", base)
				spec := tc.value
				if tc.name != "comma" {
					spec = c.write("channels.txt", []byte(tc.value))
				}
				app := filepath.Join(c.dir, "app")
				jar := filepath.Join(c.dir, "jar")
				if e := os.Mkdir(jar, 0755); e != nil {
					t.Fatal(e)
				}
				c.must(c.put("app-"+tool, spec, src, app))
				if tool == "vas" {
					c.must(c.put(tool, spec, src, jar))
				} else {
					flag := "-f"
					if tc.name == "comma" {
						flag = "-c"
					}
					c.must(c.jar(tool, "batch", flag, spec, src, jar))
				}
				c.batch(app, tool, []string{"alpha", "beta"}, base)
				want := []string{"alpha", "beta"}
				if tc.name == "bom" {
					want = []string{"\ufeffalpha", "beta"}
				}
				c.batch(jar, tool, want, base)
			})
		}
	}
}
func (c *interopCase) batch(dir, tool string, want []string, base []byte) {
	c.t.Helper()
	paths, e := filepath.Glob(filepath.Join(dir, "*.apk"))
	if e != nil {
		c.t.Fatal(e)
	}
	var got []string
	for _, p := range paths {
		ch := strings.TrimSuffix(c.must(c.appRead(p, tool)), "\n")
		got = append(got, ch)
		c.checkRead(p, tool, ch)
		c.verify(p, base)
		c.compare(base, c.read(p), interopID(tool), false)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		c.t.Fatalf("batch channels=%q want=%q", got, want)
	}
}
func (h *interopHarness) metadataCases(t *testing.T, base []byte) {
	for _, tool := range []string{"vas", "walle"} {
		t.Run("metadata/coexist/"+tool, func(t *testing.T) {
			p := interopPairs(t, base)
			p = append(p, apksigblock.Pair{ID: 0x12345678, Value: []byte("custom")}, apksigblock.Pair{ID: 0x76543210, Value: []byte{1, 2, 3}})
			if tool == "vas" {
				p = append(p, apksigblock.Pair{ID: WallePairID, Value: []byte(`{"channel":"other","extra":"preserve"}`)})
			} else {
				p = append(p, apksigblock.Pair{ID: ChannelPairID, Value: []byte("other")})
			}
			h.newCase(t).roundTrip(replaceSigningPairs(t, base, p), tool, "alpha")
		})
	}
	t.Run("metadata/walle_extra", func(t *testing.T) {
		c := h.newCase(t)
		src := c.write("base.apk", base)
		out := filepath.Join(c.dir, "extra.apk")
		c.must(c.jar("walle", "put", "-c", "alpha", "-e", "time=1,type=android", src, out))
		c.checkRead(out, "walle", "alpha")
		c.verify(out, base)
		value, _, e := channelPair(interopArchive(t, c.read(out)).block, WallePairID)
		if e != nil || !bytes.Contains(value, []byte(`"time":"1"`)) {
			t.Fatalf("extra payload=%s err=%v", value, e)
		}
		clean := filepath.Join(c.dir, "clean.apk")
		c.must(c.app("remove", "--block-id", "Walle", out, clean))
		c.absent(clean, "walle")
		c.compare(base, c.read(clean), 0, false)
		c.verify(clean, base)
	})
	for _, tc := range []struct {
		name string
		data []byte
	}{{"missing", []byte(`{"extra":"x"}`)}, {"empty", []byte(`{"channel":""}`)}, {"number", []byte(`{"channel":123}`)}, {"invalid_json", []byte(`{bad`)}, {"invalid_utf8", []byte("{\"channel\":\"\xff\"}")}} {
		t.Run("metadata/invalid/"+tc.name, func(t *testing.T) {
			c := h.newCase(t)
			p := append(interopPairs(t, base), apksigblock.Pair{ID: WallePairID, Value: tc.data})
			path := c.write("bad.apk", replaceSigningPairs(t, base, p))
			if r := c.appRead(path, "walle"); r.err == nil {
				t.Fatal("invalid Walle payload accepted")
			}
			r := c.jarRead(path, "walle")
			c.must(r)
			t.Logf("reference invalid %s: %q", tc.name, r.text)
		})
	}
}
func (h *interopHarness) badCases(t *testing.T, v1, base, mixed []byte) {
	a := interopArchive(t, base)
	mutate := func(f func([]byte)) []byte { b := append([]byte(nil), base...); f(b); return b }
	cases := []struct {
		name string
		data []byte
	}{{"truncated", base[:12]}, {"eocd_length", mutateEOCD(base, func(e []byte) { binary.LittleEndian.PutUint16(e[20:22], 100) })}, {"eocd_offset", mutateEOCD(base, func(e []byte) { binary.LittleEndian.PutUint32(e[16:20], 0xffffffff) })}, {"zip64", mutateEOCD(v1, func(e []byte) { binary.LittleEndian.PutUint16(e[10:12], 0xffff) })}, {"block_magic", mutate(func(b []byte) { b[a.eocd.CDStartOffset-1] ^= 1 })}, {"block_size", mutate(func(b []byte) { b[a.block.StartOffset] ^= 1 })}, {"pair_overflow", mutate(func(b []byte) { binary.LittleEndian.PutUint64(b[a.block.StartOffset+8:], ^uint64(0)) })}, {"signature_corrupt", mutate(func(b []byte) { b[a.block.StartOffset+40] ^= 1 })}, {"content_corrupt", mutate(func(b []byte) { b[100] ^= 1 })}}
	p := append(interopPairs(t, base), apksigblock.Pair{ID: ChannelPairID, Value: []byte("one")}, apksigblock.Pair{ID: ChannelPairID, Value: []byte("two")})
	cases = append(cases, struct {
		name string
		data []byte
	}{"duplicate_pair", replaceSigningPairs(t, base, p)})
	for _, tc := range cases {
		t.Run("malformed/"+tc.name, func(t *testing.T) {
			c := h.newCase(t)
			src := c.write("base.apk", tc.data)
			c.reject(src, "vas", "alpha")
			for _, tool := range []string{"vas", "walle"} {
				input := c.write(tool+"-base.apk", tc.data)
				r := c.put(tool, "alpha", input, filepath.Join(c.dir, tool+".apk"))
				t.Logf("%s malformed exit=%v output=%.1400s", tool, r.err, r.text)
				c.compare(tc.data, c.read(input), 0, true)
			}
		})
	}
	t.Run("malformed/mixed_force_v1", func(t *testing.T) {
		c := h.newCase(t)
		c.reject(c.write("base.apk", mixed), "vas", "alpha", "--mode", "v1")
	})
}
