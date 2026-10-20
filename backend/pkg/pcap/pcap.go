package pcap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Martin2877/blue-team-box/pkg/conf"
	files "github.com/Martin2877/blue-team-box/pkg/file"
)

var PcapEnds = []string{".pcap", ".pcapng", ".cap"}

func IsPcapFile(name string) bool {
	name = strings.ToLower(name)
	for _, ext := range PcapEnds {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

type Pcaper struct {
	File   string   `json:"file"`   // 文件
	Fields []string `json:"fields"` // 字段
}

func CreatePcaper() *Pcaper {
	return &Pcaper{
		File:   "",
		Fields: []string{"frame.time", "ip.src", "ip.dst"},
	}
}

func (ins *Pcaper) Load(file string) error {
	if file == "" || !files.Exists(file) {
		return errors.New("file not exist")
	}
	ins.File = file
	return nil
}

func (ins *Pcaper) SetFields(fields []string) {
	if len(fields) > 0 {
		ins.Fields = fields
	}
}

// tsharkTimeout 从配置读取 tshark 执行超时，默认 120 秒
func tsharkTimeout() time.Duration {
	sec := conf.GlobalConfig.PcapAnalyseConfig.TsharkTimeout
	if sec <= 0 {
		sec = 120
	}
	return time.Duration(sec) * time.Second
}

// commonTsharkPaths 常见安装位置（用于探测与兜底）
func commonTsharkPaths() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			`C:\Program Files\Wireshark\tshark.exe`,
			`C:\Program Files (x86)\Wireshark\tshark.exe`,
		}
	case "darwin":
		return []string{
			"/Applications/Wireshark.app/Contents/MacOS/tshark",
			"/usr/local/bin/tshark",
			"/opt/homebrew/bin/tshark",
		}
	default:
		return []string{"/usr/bin/tshark", "/usr/local/bin/tshark", "/snap/bin/tshark"}
	}
}

// resolveOne 校验单个配置值是否可用：绝对路径/含分隔符按文件检查，裸命令名按 PATH 查找
func resolveOne(p string) (string, bool) {
	if strings.TrimSpace(p) == "" {
		return "", false
	}
	if filepath.IsAbs(p) || strings.ContainsRune(p, os.PathSeparator) {
		if files.Exists(p) {
			return p, true
		}
		return "", false
	}
	if lp, err := exec.LookPath(p); err == nil {
		return lp, true
	}
	return "", false
}

// TsharkCandidates 探测系统中可用的 tshark 路径（用于配置提示与自动填充）
func TsharkCandidates() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if p, err := exec.LookPath("tshark"); err == nil {
		add(p)
	}
	for _, c := range commonTsharkPaths() {
		if files.Exists(c) {
			add(c)
		}
	}
	return out
}

// ResolveTsharkPath 解析实际可用的 tshark 路径：
// 配置 tsharkPath -> TSHARK 环境变量 -> PATH/常见安装目录探测
func ResolveTsharkPath() (string, error) {
	cfg := ""
	if conf.GlobalConfig != nil {
		cfg = conf.GlobalConfig.PcapAnalyseConfig.TsharkPath
	}
	if p, ok := resolveOne(cfg); ok {
		return p, nil
	}
	if p, ok := resolveOne(os.Getenv("TSHARK")); ok {
		return p, nil
	}
	if c := TsharkCandidates(); len(c) > 0 {
		return c[0], nil
	}
	return "", fmt.Errorf("未找到 tshark 可执行文件（当前配置 tsharkPath: %q），请安装 Wireshark 或在「系统设置」页面配置正确的 tshark 路径", cfg)
}

// TsharkStatus 返回 tshark 配置与探测状态（供系统设置页面展示）
func TsharkStatus() map[string]interface{} {
	cfg := ""
	if conf.GlobalConfig != nil {
		cfg = conf.GlobalConfig.PcapAnalyseConfig.TsharkPath
	}
	resolved, err := ResolveTsharkPath()
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	return map[string]interface{}{
		"configured": cfg,
		"resolved":   resolved,
		"ok":         err == nil,
		"error":      errStr,
		"candidates": TsharkCandidates(),
	}
}

func (ins *Pcaper) Query(filter string) (rawMsg []byte, errByte []byte, err error) {
	tsharkPath, err := ResolveTsharkPath()
	if err != nil {
		return nil, nil, err
	}
	var fieldList = []string{}
	for _, key := range ins.Fields {
		if key == "" {
			continue
		}
		fieldList = append(fieldList, "-e", key)
	}
	args := []string{"-r", ins.File, "-T", "json"}
	args = append(args, fieldList...)
	if filter != "" {
		args = append(args, "-Y", filter)
	}
	ctx, cancel := context.WithTimeout(context.Background(), tsharkTimeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, tsharkPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout // 标准输出
	cmd.Stderr = &stderr // 标准错误
	err = cmd.Run()
	rawMsg = stdout.Bytes()
	errByte = stderr.Bytes()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("tshark 执行超时（%s）", tsharkTimeout())
		return
	}
	if err != nil {
		err = fmt.Errorf("tshark 执行失败: %v, stderr: %s", err, strings.TrimSpace(string(errByte)))
		return
	}
	return
}
