// Package pcapjs 是内置的流量包检测引擎：检测策略以 JavaScript 编写（goja 运行），
// 无需 python / suricata 等额外运行依赖；报文提取通过 Source 接口（默认 tshark）。
//
// 策略脚本约定：
//
//	var INFO = {name: "...", desc: "...", type: "attack", phase: "...", author: "..."};
//	function process(pcap, util) { return [{name, desc, status: true, src: [], dst: []}]; }
//
// pcap.query(filter, fields)      -> [{field: "首个取值"}]
// pcap.queryMulti(filter, fields) -> [{field: ["取值", ...]}]
package pcapjs

import (
	"crypto/aes"
	"crypto/cipher"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/libinjection-go"
	"github.com/dop251/goja"
)

//go:embed strategies/*.js
var builtinFS embed.FS

// UserDir 用户自定义策略目录（相对工作目录），其中的 *.js 会与内置策略一并加载，同名 ID 覆盖内置
const UserDir = "stores/strategy"

// DisabledFile 停用策略 ID 列表的持久化文件（隐藏文件，不会被 *.js 匹配为策略）
const DisabledFile = ".disabled.json"

const defaultTimeout = 60 * time.Second

// Source 报文数据源
type Source interface {
	Query(filter string, fields []string) ([]map[string][]string, error)
}

type Strategy struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Desc    string `json:"desc"`
	Type    string `json:"type"`
	Phase   string `json:"phase"`
	Author  string `json:"author"`
	Builtin bool   `json:"builtin"`
	// Input 输入类型：pcap（默认）| log——决定该策略在流量包检测还是日志检测中执行
	Input string `json:"input"`
	// Disabled 停用后不参与全量检测，也不出现在检测策略选项中
	Disabled bool `json:"disabled"`
	source   string
}

// Event 策略的一条检出结果
type Event struct {
	Strategy string `json:"strategy"`
	Name     string `json:"name"`
	Desc     string `json:"desc"`
	Type     string `json:"type,omitempty"`
	Phase    string `json:"phase,omitempty"`
	// Severity 检出等级：critical/high/medium/low/info，前端按级别着色标签
	Severity string `json:"severity,omitempty"`
	// Engine 检出引擎：流量梳理 / 行为脚本 / nuclei / 会话关联
	Engine string `json:"engine,omitempty"`
	// Rule 命中规则标识：策略脚本 ID / nuclei 模板 ID / 关联规则类型
	Rule string   `json:"rule,omitempty"`
	Src  []string `json:"src,omitempty"`
	Dst  []string `json:"dst,omitempty"`
}

type StrategyResult struct {
	Strategy string  `json:"strategy"`
	Hit      bool    `json:"hit"`
	Events   []Event `json:"events"`
	Error    string  `json:"error,omitempty"`
}

type Registry struct {
	mu         sync.RWMutex
	strategies map[string]*Strategy
}

var (
	defaultRegistry *Registry
	once            sync.Once
)

// Default 返回全局注册表（首次调用时加载）
func Default() *Registry {
	once.Do(func() {
		defaultRegistry = &Registry{strategies: map[string]*Strategy{}}
		defaultRegistry.Reload()
	})
	return defaultRegistry
}

// DisabledIDs 返回已停用的策略 ID 集合（含未成功编译的脚本 ID）
func DisabledIDs() map[string]bool {
	out := map[string]bool{}
	raw, err := os.ReadFile(filepath.Join(UserDir, DisabledFile))
	if err != nil {
		return out
	}
	var ids []string
	if json.Unmarshal(raw, &ids) != nil {
		return out
	}
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// SetDisabled 启用/停用策略并持久化到 DisabledFile；
// 停用后批量执行（Run 不传 ids）跳过该策略，调试时按 ID 单独执行不受影响
func (r *Registry) SetDisabled(id string, disabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	dis := DisabledIDs()
	if disabled {
		dis[id] = true
	} else {
		delete(dis, id)
	}
	if s := r.strategies[id]; s != nil {
		s.Disabled = disabled
	}
	ids := make([]string, 0, len(dis))
	for k := range dis {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	if err := os.MkdirAll(UserDir, 0o755); err != nil {
		return err
	}
	raw, _ := json.Marshal(ids)
	return os.WriteFile(filepath.Join(UserDir, DisabledFile), raw, 0o644)
}

// Reload 重新加载内置与用户策略
func (r *Registry) Reload() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.strategies = map[string]*Strategy{}
	entries, _ := builtinFS.ReadDir("strategies")
	for _, e := range entries {
		if data, err := builtinFS.ReadFile("strategies/" + e.Name()); err == nil {
			r.add(e.Name(), string(data), true)
		}
	}
	files, _ := filepath.Glob(filepath.Join(UserDir, "*.js"))
	for _, f := range files {
		if data, err := os.ReadFile(f); err == nil {
			r.add(filepath.Base(f), string(data), false)
		}
	}
	for id, s := range r.strategies {
		s.Disabled = DisabledIDs()[id]
	}
}

func (r *Registry) add(file, src string, builtin bool) {
	if s, err := Compile(file, src, builtin); err == nil {
		r.strategies[s.ID] = s
	}
}

// Compile 编译脚本并提取 INFO 元信息：脚本必须可执行且定义 process(pcap, util) 函数
func Compile(file, src string, builtin bool) (*Strategy, error) {
	id := strings.TrimSuffix(path.Base(file), ".js")
	vm := goja.New()
	if _, err := vm.RunString(src); err != nil {
		return nil, err
	}
	if _, ok := goja.AssertFunction(vm.Get("process")); !ok {
		return nil, fmt.Errorf("缺少 process(pcap, util) 函数")
	}
	s := &Strategy{ID: id, Name: id, Builtin: builtin, source: src}
	if info, ok := vm.Get("INFO").Export().(map[string]interface{}); ok {
		str := func(k string) string { v, _ := info[k].(string); return v }
		if n := str("name"); n != "" {
			s.Name = n
		}
		s.Desc, s.Type, s.Phase, s.Author = str("desc"), str("type"), str("phase"), str("author")
		s.Input = str("input")
	}
	return s, nil
}

// Check 校验脚本并提取元信息（不注册到策略表），用于保存前检查
func Check(code string) (*Strategy, error) {
	return Compile("script.js", code, false)
}

// RunCode 用数据源执行一段脚本源码（调试/测试用），不经过注册表
func RunCode(src Source, code string) StrategyResult {
	s, err := Compile("debug.js", code, false)
	if err != nil {
		return StrategyResult{Strategy: "debug", Events: []Event{}, Error: err.Error()}
	}
	return s.run(src, defaultTimeout)
}

// Source 返回策略脚本源码
func (s *Strategy) Source() string { return s.source }

// BuiltinIDs 返回内置策略的文件名（不含 .js），用于判断自定义脚本是否覆盖了内置策略
func BuiltinIDs() map[string]bool {
	out := map[string]bool{}
	entries, _ := builtinFS.ReadDir("strategies")
	for _, e := range entries {
		out[strings.TrimSuffix(e.Name(), ".js")] = true
	}
	return out
}

// List 按 ID 排序返回所有策略
func (r *Registry) List() []*Strategy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Strategy, 0, len(r.strategies))
	for _, s := range r.strategies {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get 按 ID 或名称查找
func (r *Registry) Get(key string) *Strategy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.strategies[key]; ok {
		return s
	}
	for _, s := range r.strategies {
		if s.Name == key {
			return s
		}
	}
	return nil
}

// Run 对 pcap 数据源执行指定策略（ids 为空则全部 pcap 策略），返回每个策略的结果
func (r *Registry) Run(src Source, ids []string) ([]StrategyResult, error) {
	return r.RunProgress(src, ids, nil)
}

// RunLog 对日志数据源执行日志类策略（INFO.input == "log"），ids 为空则全部日志策略
func (r *Registry) RunLog(src Source, ids []string, onDone func(StrategyResult)) ([]StrategyResult, error) {
	return r.runFor(src, ids, onDone, "log")
}

// RunProgress 与 Run 相同，但每个策略执行完成时回调 onDone，
// 用于实时进度/结果上报。onDone 在并发协程中调用，实现需保证线程安全。
func (r *Registry) RunProgress(src Source, ids []string, onDone func(StrategyResult)) ([]StrategyResult, error) {
	return r.runFor(src, ids, onDone, "pcap")
}

// runFor 按策略输入类型执行：input 为 "pcap" 时跳过日志策略，"log" 时只跑日志策略；
// 显式 ids 不受类型限制（调试用）
func (r *Registry) runFor(src Source, ids []string, onDone func(StrategyResult), input string) ([]StrategyResult, error) {
	var list []*Strategy
	if len(ids) == 0 {
		for _, s := range r.List() {
			sInput := s.Input
			if sInput == "" {
				sInput = "pcap"
			}
			if !s.Disabled && sInput == input {
				list = append(list, s)
			}
		}
	}
	for _, id := range ids {
		s := r.Get(id)
		if s == nil {
			return nil, fmt.Errorf("找不到检测策略: %s", id)
		}
		list = append(list, s)
	}
	cached := newCachedSource(src)
	results := make([]StrategyResult, len(list))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, s := range list {
		wg.Add(1)
		go func(i int, s *Strategy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = s.run(cached, defaultTimeout)
			if onDone != nil {
				onDone(results[i])
			}
		}(i, s)
	}
	wg.Wait()
	return results, nil
}

func (s *Strategy) run(src Source, timeout time.Duration) (res StrategyResult) {
	res = StrategyResult{Strategy: s.ID, Events: []Event{}}
	vm := goja.New()
	timer := time.AfterFunc(timeout, func() { vm.Interrupt("策略执行超时") })
	defer timer.Stop()
	defer func() {
		if rec := recover(); rec != nil {
			res.Error = fmt.Sprint(rec)
		}
	}()

	if _, err := vm.RunString(s.source); err != nil {
		res.Error = err.Error()
		return
	}
	query := func(multi bool) func(call goja.FunctionCall) goja.Value {
		return func(call goja.FunctionCall) goja.Value {
			filter := ""
			if a := call.Argument(0); !goja.IsUndefined(a) && !goja.IsNull(a) {
				filter = a.String()
			}
			var fields []string
			if err := vm.ExportTo(call.Argument(1), &fields); err != nil {
				panic(vm.NewTypeError("fields 必须是字符串数组"))
			}
			rows, err := src.Query(filter, fields)
			if err != nil {
				panic(vm.NewGoError(err))
			}
			out := make([]interface{}, len(rows))
			for i, row := range rows {
				m := make(map[string]interface{}, len(row))
				for k, v := range row {
					if multi {
						m[k] = v
					} else if len(v) > 0 {
						m[k] = v[0]
					}
				}
				out[i] = m
			}
			return vm.ToValue(out)
		}
	}
	pcapObj := vm.NewObject()
	_ = pcapObj.Set("query", query(false))
	_ = pcapObj.Set("queryMulti", query(true))
	if s.Input == "log" {
		// log.lines() 返回全部日志条目（等价 query("", [])），便于行为脚本自行聚合
		_ = pcapObj.Set("lines", func(call goja.FunctionCall) goja.Value {
			rows, err := src.Query("", nil)
			if err != nil {
				panic(vm.NewGoError(err))
			}
			out := make([]interface{}, len(rows))
			for i, row := range rows {
				m := make(map[string]interface{}, len(row))
				for k, v := range row {
					if len(v) > 0 {
						m[k] = v[0]
					}
				}
				out[i] = m
			}
			return vm.ToValue(out)
		})
	}
	util := vm.NewObject()
	for k, v := range utilFuncs() {
		_ = util.Set(k, v)
	}

	fn, _ := goja.AssertFunction(vm.Get("process"))
	ret, err := fn(goja.Undefined(), pcapObj, util)
	if err != nil {
		res.Error = err.Error()
		return
	}
	if goja.IsUndefined(ret) || goja.IsNull(ret) {
		return
	}
	var items []map[string]interface{}
	if err := vm.ExportTo(ret, &items); err != nil {
		res.Error = "process 返回值必须是事件数组"
		return
	}
	for _, it := range items {
		if st, ok := it["status"].(bool); ok && !st {
			continue
		}
		ev := Event{Strategy: s.Name, Type: s.Type, Phase: s.Phase, Engine: "行为脚本", Rule: s.ID}
		ev.Name, _ = it["name"].(string)
		ev.Desc, _ = it["desc"].(string)
		ev.Severity, _ = it["severity"].(string)
		ev.Src, ev.Dst = toStrings(it["src"]), toStrings(it["dst"])
		if ev.Name == "" {
			ev.Name = s.Name
		}
		res.Events = append(res.Events, ev)
	}
	res.Hit = len(res.Events) > 0
	return
}

func toStrings(v interface{}) []string {
	var out []string
	switch t := v.(type) {
	case []interface{}:
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
	case []string:
		out = t
	case string:
		out = []string{t}
	}
	return out
}

func utilFuncs() map[string]interface{} {
	return map[string]interface{}{
		"hexDecode": func(s string) string {
			b, err := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(s, ":", ""), " ", ""))
			if err != nil {
				return ""
			}
			return string(b)
		},
		// body: tshark 的 http.file_data / tcp.payload 为十六进制，能解码则解码，否则原样返回
		"body": func(s string) string {
			if b, err := hex.DecodeString(strings.ReplaceAll(s, ":", "")); err == nil && len(s) > 0 {
				return string(b)
			}
			return s
		},
		"b64Decode": func(s string) string {
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				if b, err := enc.DecodeString(s); err == nil {
					return string(b)
				}
			}
			return ""
		},
		"urlDecode": func(s string) string {
			if d, err := url.QueryUnescape(s); err == nil {
				return d
			}
			return s
		},
		// sqli: libinjection 检测，命中返回指纹，否则空串
		"sqli": func(s string) string {
			if ok, fp := libinjection.IsSQLi(s); ok {
				return string(fp)
			}
			return ""
		},
		// aesCbcDecrypt: base64 密文（前 16 字节为 IV）+ base64 密钥，失败返回空串，结果按 Latin-1 映射为字符串（如 shiro rememberMe）
		"aesCbcDecrypt": func(data, key string) string {
			ct, err1 := base64.StdEncoding.DecodeString(data)
			k, err2 := base64.StdEncoding.DecodeString(key)
			if err1 != nil || err2 != nil || len(ct) < 32 || (len(ct)-16)%aes.BlockSize != 0 {
				return ""
			}
			block, err := aes.NewCipher(k)
			if err != nil {
				return ""
			}
			out := make([]byte, len(ct)-16)
			cipher.NewCBCDecrypter(block, ct[:16]).CryptBlocks(out, ct[16:])
			r := make([]rune, len(out))
			for i, b := range out {
				r[i] = rune(b)
			}
			return string(r)
		},
		"unique": func(a []string) []string {
			seen := map[string]bool{}
			out := []string{}
			for _, v := range a {
				if !seen[v] {
					seen[v] = true
					out = append(out, v)
				}
			}
			sort.Strings(out)
			return out
		},
	}
}
