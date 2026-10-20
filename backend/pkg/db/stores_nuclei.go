package db

import (
	"strings"

	"github.com/Martin2877/blue-team-box/pkg/file"
	"gorm.io/gorm"
)

// MetaVersion 模板元信息提取版本，低于该值的记录会被重新提取
const MetaVersion = 1

// NucleiTemplate nuclei 检测模板，内容以 gzip 压缩存入 content
type NucleiTemplate struct {
	gorm.Model
	Id          int    `gorm:"primary_key" json:"id"`
	Name        string `gorm:"column:name" json:"name" binding:"required"`
	Sha1        string `gorm:"column:sha_1" json:"sha_1"`
	Size        int    `json:"size"`
	Enabled     bool   `gorm:"column:enabled" json:"enabled"`
	Description string `json:"description"`
	// Path 模板相对路径（保留目录结构，字典相对引用依赖于此）
	Path        string `gorm:"column:path;index" json:"path"`
	TemplateId  string `gorm:"column:template_id;index" json:"template_id"`
	Title       string `gorm:"column:title" json:"title"`
	Severity    string `gorm:"column:severity;index" json:"severity"`
	Tags        string `gorm:"column:tags" json:"tags"`
	Author      string `gorm:"column:author" json:"author"`
	CVE         string `gorm:"column:cve" json:"cve"`
	Protocols   string `gorm:"column:protocols" json:"protocols"`
	ParseError  string `gorm:"column:parse_error" json:"parse_error"`
	Refs        string `gorm:"column:refs" json:"refs"`
	MissingRefs string `gorm:"column:missing_refs" json:"missing_refs"`
	Source      string `gorm:"column:source" json:"source"`
	MetaVer     int    `gorm:"column:meta_ver" json:"-"`
	// Content 以 gzip 压缩存储的模板内容，不通过 JSON 输出
	Content []byte `gorm:"column:content" json:"-"`
}

// SetContent 以 gzip 压缩形式写入原始内容
func (tpl *NucleiTemplate) SetContent(raw []byte) {
	if compressed, err := file.GzipBytes(raw); err == nil {
		tpl.Content = compressed
	}
}

// GetContent 解压返回原始内容
func (tpl *NucleiTemplate) GetContent() ([]byte, error) {
	return file.GunzipBytes(tpl.Content)
}

type NucleiTemplateSearchField struct {
	Search   string
	Severity string
	Tag      string
	Protocol string
	// Status: ok | error | passive | active
	Status  string
	Enabled string // "true" | "false" | ""
}

func (f *NucleiTemplateSearchField) apply(db *gorm.DB) *gorm.DB {
	if f.Search != "" {
		like := "%" + f.Search + "%"
		db = db.Where("name like ? or path like ? or template_id like ? or title like ? or sha_1 like ? or cve like ? or tags like ?", like, like, like, like, like, like, like)
	}
	if f.Severity != "" {
		db = db.Where("severity = ?", f.Severity)
	}
	if f.Tag != "" {
		db = db.Where("(',' || tags || ',') like ?", "%,"+f.Tag+",%")
	}
	if f.Protocol != "" {
		db = db.Where("(',' || protocols || ',') like ?", "%,"+f.Protocol+",%")
	}
	switch f.Status {
	case "error":
		db = db.Where("parse_error <> ''")
	case "ok":
		db = db.Where("parse_error = ''")
	case "passive":
		db = db.Where("parse_error = '' and (',' || protocols || ',') like ?", "%,http,%")
	case "active":
		db = db.Where("parse_error <> '' or (',' || protocols || ',') not like ?", "%,http,%")
	}
	switch strings.ToLower(f.Enabled) {
	case "true":
		db = db.Where("enabled = ?", true)
	case "false":
		db = db.Where("enabled = ?", false)
	}
	return db
}

func GetNucleiTemplate(id int) (tpl NucleiTemplate) {
	GlobalDB.Model(&NucleiTemplate{}).Where("id = ?", id).First(&tpl)
	return
}

func GetNucleiTemplateByPath(p string) (tpl NucleiTemplate) {
	GlobalDB.Model(&NucleiTemplate{}).Where("path = ?", p).First(&tpl)
	return
}

func GetNucleiTemplateByTID(tid string) (tpl NucleiTemplate) {
	GlobalDB.Model(&NucleiTemplate{}).Where("template_id = ?", tid).First(&tpl)
	return
}

func GetNucleiTemplateBySha1(sha1 string) (tpl NucleiTemplate) {
	GlobalDB.Model(&NucleiTemplate{}).Where("sha_1 = ?", sha1).First(&tpl)
	return
}

func AddNucleiTemplate(tpl NucleiTemplate) bool {
	GlobalDB.Create(&tpl)
	return true
}

func DeleteNucleiTemplate(id int) bool {
	GlobalDB.Model(&NucleiTemplate{}).Where("id = ?", id).Delete(&NucleiTemplate{})
	return true
}

func GetNucleiTemplates(page int, pageSize int, field *NucleiTemplateSearchField) (templates []NucleiTemplate) {
	// 列表查询排除 content 大字段，避免每次拉取全量二进制内容
	db := field.apply(GlobalDB.Model(&NucleiTemplate{}).Omit("Content"))
	if !(page > 0 && pageSize > 0) {
		page = 1
		pageSize = 10
	}
	db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize).Find(&templates)
	return
}

// GetEnabledNucleiTemplates 返回全部启用模板（含 content），供引擎加载
func GetEnabledNucleiTemplates() (templates []NucleiTemplate) {
	GlobalDB.Model(&NucleiTemplate{}).Where("enabled = ?", true).Find(&templates)
	return
}

// GetNucleiTemplatesStaleMeta 返回元信息未提取（或版本过旧、曾解析失败）的模板（含 content）。
// parse_error 非空的记录一并返回，使引擎修复后能在下一次加载时自动重试。
func GetNucleiTemplatesStaleMeta() (templates []NucleiTemplate) {
	GlobalDB.Model(&NucleiTemplate{}).Where("coalesce(meta_ver,0) < ? or path = '' or path is null or parse_error <> ''", MetaVersion).Find(&templates)
	return
}

func GetNucleiTemplateTotal(field *NucleiTemplateSearchField) (total int64) {
	field.apply(GlobalDB.Model(&NucleiTemplate{})).Count(&total)
	return
}

func GetNucleiTemplateIds(field *NucleiTemplateSearchField) (ids []int) {
	field.apply(GlobalDB.Model(&NucleiTemplate{})).Pluck("id", &ids)
	return
}

func ExistNucleiTemplateById(id int) bool {
	var tpl NucleiTemplate
	GlobalDB.Model(&NucleiTemplate{}).Where("id = ?", id).First(&tpl)
	return tpl.Id > 0
}

func ExistNucleiTemplateByName(name string) bool {
	var tpl NucleiTemplate
	GlobalDB.Model(&NucleiTemplate{}).Where("name = ?", name).First(&tpl)
	return tpl.Id > 0
}

func ExistNucleiTemplateBySha1(sha1 string) bool {
	var tpl NucleiTemplate
	GlobalDB.Model(&NucleiTemplate{}).Where("sha_1 = ?", sha1).First(&tpl)
	return tpl.Id > 0
}

// NucleiStats 概览统计
type NucleiStats struct {
	Total     int64            `json:"total"`
	Enabled   int64            `json:"enabled"`
	Errors    int64            `json:"errors"`
	Passive   int64            `json:"passive"`
	Missing   int64            `json:"missing_refs"`
	Severity  map[string]int64 `json:"severity"`
	Protocols map[string]int64 `json:"protocols"`
	TopTags   []NameCount      `json:"top_tags"`
}

type NameCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func GetNucleiStats() NucleiStats {
	st := NucleiStats{Severity: map[string]int64{}, Protocols: map[string]int64{}}
	m := func() *gorm.DB { return GlobalDB.Model(&NucleiTemplate{}) }
	m().Count(&st.Total)
	m().Where("enabled = ?", true).Count(&st.Enabled)
	m().Where("parse_error <> ''").Count(&st.Errors)
	m().Where("parse_error = '' and (',' || protocols || ',') like ?", "%,http,%").Count(&st.Passive)
	m().Where("missing_refs <> ''").Count(&st.Missing)
	var rows []struct {
		Severity  string
		Tags      string
		Protocols string
	}
	m().Select("severity, tags, protocols").Find(&rows)
	tagCount := map[string]int64{}
	for _, r := range rows {
		st.Severity[r.Severity]++
		for _, p := range splitCSV(r.Protocols) {
			st.Protocols[p]++
		}
		for _, t := range splitCSV(r.Tags) {
			tagCount[t]++
		}
	}
	for n, c := range tagCount {
		st.TopTags = append(st.TopTags, NameCount{n, c})
	}
	sortNameCounts(st.TopTags)
	if len(st.TopTags) > 20 {
		st.TopTags = st.TopTags[:20]
	}
	return st
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func sortNameCounts(l []NameCount) {
	for i := 1; i < len(l); i++ {
		for j := i; j > 0 && (l[j].Count > l[j-1].Count || (l[j].Count == l[j-1].Count && l[j].Name < l[j-1].Name)); j-- {
			l[j], l[j-1] = l[j-1], l[j]
		}
	}
}

// NucleiResource 引擎资源：字典、payload 文件、helpers、workflows、配置等
type NucleiResource struct {
	gorm.Model
	Id          int    `gorm:"primary_key" json:"id"`
	Path        string `gorm:"column:path;uniqueIndex" json:"path"`
	Name        string `gorm:"column:name" json:"name"`
	Kind        string `gorm:"column:kind;index" json:"kind"`
	Sha1        string `gorm:"column:sha_1" json:"sha_1"`
	Size        int    `json:"size"`
	Lines       int    `json:"lines"`
	Description string `json:"description"`
	Content     []byte `gorm:"column:content" json:"-"`
}

func (r *NucleiResource) SetContent(raw []byte) {
	if compressed, err := file.GzipBytes(raw); err == nil {
		r.Content = compressed
	}
}

func (r *NucleiResource) GetContent() ([]byte, error) { return file.GunzipBytes(r.Content) }

type NucleiResourceSearchField struct {
	Search string
	Kind   string
}

func (f *NucleiResourceSearchField) apply(db *gorm.DB) *gorm.DB {
	if f.Search != "" {
		db = db.Where("path like ?", "%"+f.Search+"%")
	}
	if f.Kind != "" {
		db = db.Where("kind = ?", f.Kind)
	}
	return db
}

func GetNucleiResources(page, pageSize int, field *NucleiResourceSearchField) (list []NucleiResource) {
	db := field.apply(GlobalDB.Model(&NucleiResource{}).Omit("Content"))
	if !(page > 0 && pageSize > 0) {
		page, pageSize = 1, 10
	}
	db.Offset((page - 1) * pageSize).Order("path").Limit(pageSize).Find(&list)
	return
}

func GetNucleiResourceTotal(field *NucleiResourceSearchField) (total int64) {
	field.apply(GlobalDB.Model(&NucleiResource{})).Count(&total)
	return
}

func GetNucleiResource(id int) (r NucleiResource) {
	GlobalDB.Model(&NucleiResource{}).Where("id = ?", id).First(&r)
	return
}

func GetNucleiResourceByPath(p string) (r NucleiResource) {
	GlobalDB.Model(&NucleiResource{}).Where("path = ?", p).First(&r)
	return
}

func GetAllNucleiResources() (list []NucleiResource) {
	GlobalDB.Model(&NucleiResource{}).Find(&list)
	return
}

func DeleteNucleiResource(id int) {
	GlobalDB.Unscoped().Where("id = ?", id).Delete(&NucleiResource{})
}

func CountNucleiResources() (n int64) {
	GlobalDB.Model(&NucleiResource{}).Count(&n)
	return
}

// NucleiSetting 引擎配置键值
type NucleiSetting struct {
	Key   string `gorm:"column:key;primaryKey" json:"key"`
	Value string `gorm:"column:value" json:"value"`
}

func GetNucleiSetting(key string) string {
	var s NucleiSetting
	GlobalDB.Where("`key` = ?", key).First(&s)
	return s.Value
}

func SetNucleiSetting(key, value string) error {
	return GlobalDB.Save(&NucleiSetting{Key: key, Value: value}).Error
}
