// Package vuln 是“漏洞检测引擎”的服务层：负责 nuclei 规则/字典/配置的管理，
// 并向各检测流程（流量包检测、HTTP 深度解析、攻击载荷检测）提供已编译、可缓存的引擎。
package vuln

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"reflect"
	"strings"
	"sync"

	"github.com/Martin2877/blue-team-box/engine/nuclei"
	"github.com/Martin2877/blue-team-box/pkg/db"
	utils "github.com/Martin2877/blue-team-box/pkg/util"
	"gorm.io/gorm"
)

const (
	MaxFileSize = 10 << 20
	MaxZipSize  = 200 << 20
	settingKey  = "vuln"
)

// Settings 漏洞检测引擎的全局配置
type Settings struct {
	MinSeverity    string   `json:"min_severity"`
	IncludeTags    []string `json:"include_tags"`
	ExcludeTags    []string `json:"exclude_tags"`
	ExcludeIDs     []string `json:"exclude_ids"`
	DefaultEnable  string   `json:"default_enable"` // all | high | none
	ExpandPayloads bool     `json:"expand_payloads"`
	ExpandLimit    int      `json:"expand_limit"`
}

func DefaultSettings() Settings {
	return Settings{DefaultEnable: "all", ExpandPayloads: true, ExpandLimit: 100}
}

func GetSettings() Settings {
	st := DefaultSettings()
	if db.GlobalDB != nil {
		if v := db.GetNucleiSetting(settingKey); v != "" {
			_ = json.Unmarshal([]byte(v), &st)
		}
	}
	if st.ExpandLimit <= 0 {
		st.ExpandLimit = 100
	}
	return st
}

func SaveSettings(st Settings) error {
	switch st.DefaultEnable {
	case "all", "high", "none":
	default:
		st.DefaultEnable = "all"
	}
	if st.ExpandLimit <= 0 || st.ExpandLimit > 1000 {
		st.ExpandLimit = 100
	}
	b, _ := json.Marshal(st)
	err := db.SetNucleiSetting(settingKey, string(b))
	Invalidate()
	return err
}

var (
	mu        sync.RWMutex
	cached    *nuclei.Engine
	cachedErr []error
	metaOnce  sync.Mutex
)

// Invalidate 模板、字典或配置变更后调用，使缓存的编译结果失效
func Invalidate() {
	mu.Lock()
	cached, cachedErr = nil, nil
	mu.Unlock()
}

// Cached 返回已构建的引擎缓存与加载错误；尚未构建返回 nil, nil
func Cached() (*nuclei.Engine, []error) {
	mu.RLock()
	defer mu.RUnlock()
	return cached, cachedErr
}

// Warmup 后台异步构建引擎缓存（已缓存则直接返回），可安全重复调用
func Warmup() {
	if eng, _ := Cached(); eng == nil {
		go func() { _, _ = Load() }()
	}
}

// ResourceReader 从数据库字典资源中按引用路径读取内容；引用路径可以带任意层级的前缀目录
func ResourceReader() nuclei.ResourceReader {
	return func(ref string) ([]byte, bool) {
		ref = strings.TrimPrefix(strings.ReplaceAll(ref, "\\", "/"), "./")
		segs := strings.Split(ref, "/")
		for i := range segs {
			cand := strings.Join(segs[i:], "/")
			if cand == "" {
				break
			}
			r := db.GetNucleiResourceByPath(cand)
			if r.Id == 0 {
				var rows []db.NucleiResource
				db.GlobalDB.Where("path like ?", "%/"+cand).Limit(1).Find(&rows)
				if len(rows) > 0 {
					r = rows[0]
				}
			}
			if r.Id > 0 {
				if raw, err := r.GetContent(); err == nil {
					return raw, true
				}
			}
		}
		return nil, false
	}
}

// ParseOpts 按当前配置生成模板解析选项
func ParseOpts() nuclei.ParseOptions {
	st := GetSettings()
	return nuclei.ParseOptions{Resources: ResourceReader(), ExpandPayloads: st.ExpandPayloads, ExpandLimit: st.ExpandLimit}
}

// NewEngine 返回按当前配置设置好解析选项、但未加载任何模板的引擎（用于校验、调试）
func NewEngine() *nuclei.Engine {
	e := nuclei.New()
	e.Parse = ParseOpts()
	return e
}

func (s Settings) options() nuclei.Options {
	return nuclei.Options{MinSeverity: s.MinSeverity, Tags: s.IncludeTags, ExcludeTags: s.ExcludeTags, ExcludeIDs: s.ExcludeIDs}
}

// Load 返回加载了全部启用模板的引擎（已缓存；Options 来自全局配置）
func Load() (*nuclei.Engine, []error) { return LoadWith("", nil) }

// LoadWith 与 Load 相同，但调用方指定的最低严重级别、标签优先于全局配置
func LoadWith(minSeverity string, tags []string) (*nuclei.Engine, []error) {
	if db.GlobalDB == nil {
		return nuclei.New(), nil
	}
	mu.RLock()
	eng, errs := cached, cachedErr
	mu.RUnlock()
	if eng == nil {
		mu.Lock()
		if cached == nil {
			cached, cachedErr = build()
		}
		eng, errs = cached, cachedErr
		mu.Unlock()
	}
	opts := GetSettings().options()
	if minSeverity != "" {
		opts.MinSeverity = minSeverity
	}
	if len(tags) > 0 {
		opts.Tags = tags
	}
	return eng.With(opts), errs
}

func build() (*nuclei.Engine, []error) {
	EnsureMeta()
	eng := NewEngine()
	var errs []error
	for _, t := range db.GetEnabledNucleiTemplates() {
		raw, err := t.GetContent()
		if err == nil {
			err = eng.AddTemplate(templateKey(&t), raw)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", templateKey(&t), err))
		}
	}
	return eng, errs
}

func templateKey(t *db.NucleiTemplate) string {
	if t.Path != "" {
		return t.Path
	}
	return t.Name
}

// FillMeta 解析模板并写入元信息（id/严重级别/标签/协议/字典引用/解析状态）
func FillMeta(t *db.NucleiTemplate, raw []byte, rr nuclei.ResourceReader) {
	t.Sha1, t.Size, t.MetaVer = utils.Sha1Bytes(raw), len(raw), db.MetaVersion
	t.TemplateId, t.Title, t.Severity, t.Tags, t.Author, t.CVE, t.Protocols = "", "", "info", "", "", "", ""
	t.ParseError, t.Refs, t.MissingRefs = "", "", ""
	m, err := nuclei.Inspect(raw)
	if err != nil {
		t.ParseError = err.Error()
		return
	}
	t.TemplateId, t.Title, t.Severity, t.Author, t.CVE = m.ID, m.Name, m.Severity, m.Author, m.CVE
	t.Tags, t.Protocols = strings.Join(m.Tags, ","), strings.Join(m.Protocols, ",")
	if t.Description == "" {
		t.Description = m.Description
	}
	if !strings.Contains(","+t.Protocols+",", ",http,") {
		return
	}
	parsed, err := nuclei.ParseTemplateOpts(templateKey(t), raw, &nuclei.ParseOptions{Resources: rr})
	if err != nil {
		t.ParseError = err.Error()
		return
	}
	t.Refs, t.MissingRefs = strings.Join(parsed.Refs, ","), strings.Join(parsed.MissingRefs, ",")
}

// EnsureMeta 为旧数据（无路径/元信息）补全字段。
// 解析后无变化的行不写库（持续解析失败的模板仍会参与下次重试）；
// 有变化的行在单个事务内批量写入，避免逐行自动提交（每次 fsync 数百 ms）。
func EnsureMeta() {
	if db.GlobalDB == nil {
		return
	}
	metaOnce.Lock()
	defer metaOnce.Unlock()
	rows := db.GetNucleiTemplatesStaleMeta()
	if len(rows) == 0 {
		return
	}
	rr, st := ResourceReader(), GetSettings()
	var dirty []db.NucleiTemplate
	for _, t := range rows {
		before := t
		if t.Path == "" {
			t.Path = t.Name
		}
		hadErr := t.ParseError != ""
		if raw, err := t.GetContent(); err == nil {
			FillMeta(&t, raw, rr)
			// 此前因解析失败被禁用的模板，修复后按默认启用策略恢复
			if hadErr && t.ParseError == "" && !t.Enabled {
				t.Enabled = shouldEnable(st, &t)
			}
		} else {
			t.ParseError, t.MetaVer = "内容解压失败", db.MetaVersion
		}
		// Content 不参与变化比较，Save 时也不写入
		before.Content, t.Content = nil, nil
		if !reflect.DeepEqual(before, t) {
			dirty = append(dirty, t)
		}
	}
	if len(dirty) == 0 {
		return
	}
	_ = db.GlobalDB.Transaction(func(tx *gorm.DB) error {
		for i := range dirty {
			if err := tx.Omit("Content").Save(&dirty[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// shouldEnable 按“导入后默认启用策略”决定模板是否启用
func shouldEnable(st Settings, t *db.NucleiTemplate) bool {
	if t.ParseError != "" || !strings.Contains(","+t.Protocols+",", ",http,") {
		return false
	}
	switch st.DefaultEnable {
	case "none":
		return false
	case "high":
		return t.Severity == "high" || t.Severity == "critical"
	}
	return true
}

// ImportResult 导入统计
type ImportResult struct {
	Added     int    `json:"added"`
	Updated   int    `json:"updated"`
	Skipped   int    `json:"skipped"`
	Resources int    `json:"resources"`
	Failed    int    `json:"failed"`
	Message   string `json:"message"`
}

// CleanPath 规范化相对路径，拒绝目录穿越与隐藏目录
func CleanPath(p string) string {
	p = strings.Trim(strings.ReplaceAll(p, "\\", "/"), "/")
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s == "" || s == "." {
			continue
		}
		if s == ".." || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "__MACOSX") || strings.ContainsAny(s, ":*?\"<>|") {
			return ""
		}
		out = append(out, s)
	}
	return strings.Join(out, "/")
}

func hasSeg(p string, names ...string) bool {
	segs := strings.Split(strings.ToLower(p), "/")
	for _, s := range segs[:len(segs)-1] {
		for _, n := range names {
			if s == n {
				return true
			}
		}
	}
	return false
}

// Classify 判断导入文件的类别：template / resource(kind) / skip
func Classify(p string) (kind string, isTemplate bool) {
	ext := strings.ToLower(path.Ext(p))
	switch ext {
	case ".yaml", ".yml":
		switch {
		case hasSeg(p, "workflows", "workflow"):
			return "workflow", false
		case hasSeg(p, "profiles", "config"):
			return "profile", false
		case hasSeg(p, "helpers"):
			return "helper", false
		}
		return "", true
	case ".txt", ".lst", ".list", ".dic", ".dict":
		if hasSeg(p, "payloads") {
			return "payload", false
		}
		return "wordlist", false
	case ".json", ".csv", ".conf":
		if hasSeg(p, "helpers", "payloads", "wordlists", "dict", "dicts") {
			return "payload", false
		}
	}
	return "skip", false
}

// SaveResource 新增或更新字典资源，返回是否新增
func SaveResource(p, kind string, raw []byte) (added bool) {
	return saveResource(db.GlobalDB, p, kind, raw)
}

// saveResource 同 SaveResource，tx 可传事务连接（批量导入场景避免逐行自动提交）
func saveResource(tx *gorm.DB, p, kind string, raw []byte) (added bool) {
	sha := utils.Sha1Bytes(raw)
	var cur db.NucleiResource
	tx.Model(&db.NucleiResource{}).Where("path = ?", p).First(&cur)
	lines := bytes.Count(raw, []byte("\n")) + 1
	if cur.Id > 0 {
		if cur.Sha1 != sha {
			cur.Sha1, cur.Size, cur.Lines, cur.Kind = sha, len(raw), lines, kind
			cur.SetContent(raw)
			tx.Save(&cur)
		}
		return false
	}
	r := db.NucleiResource{Path: p, Name: path.Base(p), Kind: kind, Sha1: sha, Size: len(raw), Lines: lines}
	r.SetContent(raw)
	tx.Create(&r)
	return true
}

// SaveTemplate 新增或更新模板（按路径），返回 (added, changed)
func SaveTemplate(p, source string, raw []byte, st Settings, rr nuclei.ResourceReader) (added, changed bool) {
	return saveTemplate(db.GlobalDB, p, source, raw, st, rr)
}

// saveTemplate 同 SaveTemplate，tx 可传事务连接
func saveTemplate(tx *gorm.DB, p, source string, raw []byte, st Settings, rr nuclei.ResourceReader) (added, changed bool) {
	var cur db.NucleiTemplate
	tx.Model(&db.NucleiTemplate{}).Where("path = ?", p).First(&cur)
	if cur.Id > 0 && cur.Sha1 == utils.Sha1Bytes(raw) {
		return false, false
	}
	t := cur
	t.Path, t.Name = p, path.Base(p)
	if source != "" {
		t.Source = source
	}
	FillMeta(&t, raw, rr)
	t.SetContent(raw)
	if cur.Id > 0 {
		tx.Save(&t)
		return false, true
	}
	t.Enabled = shouldEnable(st, &t)
	tx.Create(&t)
	return true, true
}

// ImportZip 批量导入 zip 包：目录结构保留；yaml 去模板表，字典/helpers/workflows 等去资源表
func ImportZip(data []byte, source string) ImportResult {
	var res ImportResult
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		res.Message = "zip 解析失败: " + err.Error()
		return res
	}
	// 去掉整包共用的根目录（如 nuclei-templates-10.0.0/）
	root, same := "", true
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		first, _, ok := strings.Cut(strings.ReplaceAll(f.Name, "\\", "/"), "/")
		if !ok {
			same = false
			break
		}
		if root == "" {
			root = first
		} else if root != first {
			same = false
			break
		}
	}
	type entry struct {
		path string
		raw  []byte
		kind string
	}
	var tpls, ress []entry
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if same && root != "" {
			name = strings.TrimPrefix(name, root+"/")
		}
		p := CleanPath(name)
		if p == "" {
			res.Skipped++
			continue
		}
		kind, isTpl := Classify(p)
		if kind == "skip" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			res.Failed++
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(rc, MaxFileSize+1))
		rc.Close()
		if err != nil || len(raw) == 0 || len(raw) > MaxFileSize {
			res.Skipped++
			continue
		}
		if isTpl {
			tpls = append(tpls, entry{p, raw, ""})
		} else {
			ress = append(ress, entry{p, raw, kind})
		}
	}
	// 资源与模板各用一个事务：资源先提交，模板解析时的 ResourceReader（读 GlobalDB）才能读到
	if err := db.GlobalDB.Transaction(func(tx *gorm.DB) error {
		for _, e := range ress {
			if saveResource(tx, e.path, e.kind, e.raw) {
				res.Resources++
			}
		}
		return nil
	}); err != nil {
		res.Message = "资源入库失败: " + err.Error()
		return res
	}
	st, rr := GetSettings(), ResourceReader()
	if err := db.GlobalDB.Transaction(func(tx *gorm.DB) error {
		for _, e := range tpls {
			a, c := saveTemplate(tx, e.path, source, e.raw, st, rr)
			switch {
			case a:
				res.Added++
			case c:
				res.Updated++
			default:
				res.Skipped++
			}
		}
		return nil
	}); err != nil {
		res.Message = "模板入库失败: " + err.Error()
		return res
	}
	Invalidate()
	res.Message = fmt.Sprintf("新增模板 %d、更新 %d、跳过 %d，导入字典/资源 %d", res.Added, res.Updated, res.Skipped, res.Resources)
	return res
}
