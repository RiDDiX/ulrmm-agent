// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	rmm "git.riddix.de/RiDDiX/ulrmm-agent/shared"
	"github.com/elastic/go-sysinfo"
	ping "github.com/go-ping/ping"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/ugorji/go/codec"
)

// encodeMsgpack uses the codec's default handle on purpose: strings and
// byte slices go out as msgpack raw (no str8, no bin), which the server
// decodes as text.
func encodeMsgpack(v interface{}) ([]byte, error) {
	var b []byte
	err := codec.NewEncoderBytes(&b, new(codec.MsgpackHandle)).Encode(v)
	return b, err
}

// CleanString drops NUL bytes and invalid UTF-8; the server's msgpack
// decoder refuses both. Windows output that is not UTF-8 is read as the
// OEM code page first, so umlauts and the like survive.
func CleanString(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	if !utf8.ValidString(s) {
		s = decodeLines(s, legacyDecoders())
	}
	return strings.ToValidUTF8(s, "")
}

func StripAll(s string) string {
	return strings.TrimSpace(s)
}

// Strips the quotes around a JSON string answer.
func DjangoStringResp(s string) string {
	return strings.Trim(s, `"`)
}

// ByteCountSI formats sizes in steps of 1024 with a lower-case k: 1536 is
// "1.5 kB".
func ByteCountSI(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

func removeWinNewLines(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

func removeNewlines(s string) string {
	return strings.ReplaceAll(s, "\n", "")
}

func contains(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// GenerateAgentID returns 40 random ASCII letters.
func GenerateAgentID() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 40)
	max := big.NewInt(int64(len(letters)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b[i] = letters[n.Int64()]
	}
	return string(b)
}

// randRange returns an integer in [min, max), min when the range is empty.
func randRange(min, max int) int {
	if max <= min {
		return min
	}
	return mrand.Intn(max-min) + min
}

func randomCheckDelay() {
	time.Sleep(time.Duration(randRange(300, 950)) * time.Millisecond)
}

// regRangeToInt draws from a "min,max" registry override; 0 (use the
// default) when the text is not such a range.
func regRangeToInt(s string) int {
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return 0
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || lo <= 0 || hi <= lo {
		return 0
	}
	return randRange(lo, hi)
}

func (a *Agent) TotalRAM() float64 {
	total, _, err := memTotalUsed()
	if err != nil {
		return 8.0
	}
	return math.Ceil(float64(total) / (1 << 30))
}

// go-sysinfo, else gopsutil: go-sysinfo has no FreeBSD provider
func memTotalUsed() (total, used uint64, err error) {
	if h, herr := sysinfo.Host(); herr == nil {
		if m, merr := h.Memory(); merr == nil && m.Total > 0 {
			return m.Total, m.Used, nil
		}
	}
	vm, err := mem.VirtualMemory()
	if err == nil && vm.Total == 0 {
		err = errors.New("total memory is 0")
	}
	if err != nil {
		return 0, 0, err
	}
	return vm.Total, vm.Used, nil
}

func (a *Agent) BootTime() int64 {
	if h, err := sysinfo.Host(); err == nil {
		return h.Info().BootTime.Unix()
	}
	if t, err := host.BootTime(); err == nil && t > 0 {
		return int64(t)
	}
	return 1000
}

// PublicIP asks the lookup URLs in turn. An IPv6 answer is swapped for an
// IPv4 one from the fallback URL when that has one. Without any valid
// answer the last body is returned, or "error" when nothing answered.
func (a *Agent) PublicIP() string {
	get := func(u string) (string, error) {
		// the RMM answers it in branded builds: its trust applies
		client, err := a.httpClient(u, 4*time.Second)
		if err != nil {
			return "", err
		}
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", a.AgentHeader)
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return StripAll(string(b)), err
	}

	last := "error"
	for _, u := range pubIPURLs() {
		ip, err := get(u)
		if err != nil {
			continue
		}
		last = ip
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			return ip
		}
		v4, err := get(pubIPFallbackURL())
		if err != nil {
			return ip
		}
		if p := net.ParseIP(v4); p != nil && p.To4() != nil {
			return v4
		}
	}
	return last
}

type PingResponse struct {
	Status string
	Output string
}

// DoPing sends three ICMP echos (raw socket, needs root or admin).
func DoPing(host string) (PingResponse, error) {
	p, err := ping.NewPinger(host)
	if err != nil {
		return PingResponse{}, err
	}
	p.SetPrivileged(true)
	p.Count, p.Size = 3, 548
	p.Interval, p.Timeout = time.Second, 5*time.Second
	var out bytes.Buffer
	p.OnRecv = func(pkt *ping.Packet) {
		fmt.Fprintf(&out, "%d bytes from %s: icmp_seq=%d time=%v\n", pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}
	p.OnFinish = func(st *ping.Statistics) {
		fmt.Fprintf(&out, "\n--- %s ping statistics ---\n", st.Addr)
		fmt.Fprintf(&out, "%d packets transmitted, %d packets received, %v%% packet loss\n", st.PacketsSent, st.PacketsRecv, st.PacketLoss)
		fmt.Fprintf(&out, "round-trip min/avg/max/stddev = %v/%v/%v/%v\n", st.MinRtt, st.AvgRtt, st.MaxRtt, st.StdDevRtt)
	}
	if err := p.Run(); err != nil {
		return PingResponse{}, err
	}
	res := PingResponse{Status: "passing", Output: out.String()}
	if st := p.Statistics(); st.PacketsRecv != st.PacketsSent && st.PacketLoss != 0 {
		res.Status = "failing"
	}
	return res, nil
}

const pyCPULoad = `import psutil
try:
    print(int(round(psutil.cpu_percent(interval=10))), end='')
except:
    print('pyerror', end='')
`

// GetCPULoadAvg samples the CPU for 10 s: with the bundled Python where it
// exists (Windows), else natively.
func (a *Agent) GetCPULoadAvg() int {
	if a.PyBin != "" && a.PyBin != "n/a" && rmm.FileExists(a.PyBin) {
		out, err := a.RunPythonCode(pyCPULoad, 13, nil)
		if err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(out)); err == nil {
				return n
			}
		}
		a.Logger.Debugln("GetCPULoadAvg(): python:", err)
	}
	p, err := cpu.Percent(10*time.Second, false)
	if err != nil || len(p) == 0 {
		a.Logger.Debugln("GetCPULoadAvg():", err)
		return 0
	}
	return int(math.Round(p[0]))
}

// RunPythonCode runs a snippet with the bundled Python. Anything on stderr
// counts as failure and is returned as the text.
func (a *Agent) RunPythonCode(code string, timeout int, args []string) (string, error) {
	f, err := os.CreateTemp(a.WinTmpDir, "*.py")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(code)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, a.PyBin, append([]string{f.Name()}, args...)...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if stderr.Len() > 0 {
		return stderr.String(), errors.New("RunPythonCode stderr")
	}
	if err != nil {
		return "", err
	}
	return stdout.String(), nil
}

// getPowershellExe and getCMDExe prefer System32: a SYSTEM service must not
// pick up a powershell.exe from a writable PATH directory.
func getPowershellExe() string {
	p := filepath.Join(os.Getenv("WINDIR"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if rmm.FileExists(p) {
		return p
	}
	if lp, err := exec.LookPath("powershell.exe"); err == nil {
		return lp
	}
	return p
}

func getCMDExe() string {
	p := filepath.Join(os.Getenv("WINDIR"), "System32", "cmd.exe")
	if rmm.FileExists(p) {
		return p
	}
	if lp, err := exec.LookPath("cmd.exe"); err == nil {
		return lp
	}
	return p
}

// nixTmpDir (agent.go) holds the script files when no tmpdir is configured:
// not listable or writable for others, but users can reach a script they
// were given (run_as_user).

// createNixTmpFile creates a script file in dir (default nixTmpDir, where
// tmp mounted noexec does not matter). Deno wants .ts.
func createNixTmpFile(dir string, shell ...string) (*os.File, error) {
	if dir == "" {
		dir = nixTmpDir
		if err := os.MkdirAll(dir, 0o711); err != nil {
			return nil, err
		}
		// on TrueNAS it sits in the world-writable /var/tmp
		if err := ownDir(dir); err != nil {
			return nil, err
		}
		if err := os.Chmod(dir, 0o711); err != nil {
			return nil, err
		}
	} else if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	pattern := "ulrmm*"
	if len(shell) > 0 && shell[0] == "deno" {
		pattern += ".ts"
	}
	return os.CreateTemp(dir, pattern)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err == nil {
		defer in.Close()
		err = writeAll(dst, in, 0o666)
	}
	return err
}

// writeAll creates or truncates dst with perm and fills it from r.
func writeAll(dst string, r io.Reader, perm os.FileMode) error {
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, r)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// safeJoin joins an archive entry to dest and refuses entries that would
// land outside of it.
func safeJoin(dest, name string) (string, error) {
	base := filepath.Clean(dest)
	p := filepath.Join(base, name)
	if p != base && !strings.HasPrefix(p, base+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive entry %q leaves the destination directory", name)
	}
	return p, nil
}

func Unzip(src, dest string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if err := unzipEntry(f, dest); err != nil {
			return err
		}
	}
	return nil
}

func unzipEntry(f *zip.File, dest string) error {
	target, err := safeJoin(dest, f.Name)
	if err != nil {
		return fmt.Errorf("%s: illegal file path", f.Name)
	}
	if f.FileInfo().IsDir() {
		return os.MkdirAll(target, 0o755)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	return writeAll(target, rc, f.Mode())
}

// ExtractTarGz unpacks directories and regular files only and returns the
// first directory of the archive as written there. Callers set the modes.
func (a *Agent) ExtractTarGz(path, destDir string) (extractedDir string, err error) {
	defer func() {
		if err != nil {
			a.Logger.Errorln("ExtractTarGz():", err)
		}
	}()
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return extractedDir, nil
		}
		if err != nil {
			return "", err
		}
		p, err := safeJoin(destDir, hdr.Name)
		if err != nil {
			return "", err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o755); err != nil {
				return "", err
			}
			if extractedDir == "" {
				extractedDir = hdr.Name
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return "", err
			}
			out, err := os.Create(p)
			if err != nil {
				return "", err
			}
			_, err = io.Copy(out, tr)
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("ExtractTarGz(): Unknown type: %v in %s", hdr.Typeflag, hdr.Name)
		}
	}
}
